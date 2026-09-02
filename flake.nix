{
  description = "Rotate shared keys for Azure services and update supported places that store them";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      project = builtins.fromTOML (builtins.readFile ./pyproject.toml);
      pname = project.project.name;
      version = project.project.version;
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python312;
        pythonPackages = pkgs.python312Packages;
        azureMgmtCognitiveServices =
          pythonPackages.azure-mgmt-cognitiveservices.overridePythonAttrs
            (_old: {
              version = "14.1.0";
              src = pkgs.fetchPypi {
                pname = "azure_mgmt_cognitiveservices";
                version = "14.1.0";
                hash = "sha256-kVGRN00K20Q4Y8IKrqLJ87nVWKhJrCt48VIkkmL9yvg=";
              };
            });
        azureAiProjects = pythonPackages.azure-ai-projects.overridePythonAttrs (_old: {
          version = "2.3.0";
          src = pkgs.fetchPypi {
            pname = "azure_ai_projects";
            version = "2.3.0";
            hash = "sha256-bjAGt7iqUcb/nbYe9KrDcX+KcSzRoYPVodNOLrM0UL0=";
          };
          dependencies = with pythonPackages; [
            azure-core
            azure-identity
            azure-storage-blob
            isodate
            openai
            typing-extensions
          ];
        });
        azureMgmtStorage = pythonPackages.azure-mgmt-storage.overridePythonAttrs (_old: {
          version = "25.1.0";
          src = pkgs.fetchPypi {
            pname = "azure_mgmt_storage";
            version = "25.1.0";
            hash = "sha256-zEvSFY/Q3YBjkUKvBtxwwRm7/W951T2kSC4LLISa98o=";
          };
          dependencies = with pythonPackages; [
            azure-mgmt-core
            isodate
            typing-extensions
          ];
        });
        azureMgmtWeb = pythonPackages.azure-mgmt-web.overridePythonAttrs (_old: {
          version = "11.0.1";
          src = pkgs.fetchPypi {
            pname = "azure_mgmt_web";
            version = "11.0.1";
            hash = "sha256-HOjtf9aeHdTIIKKXZWQ+k5S1j0KLUBM2QT1RfAJ6FFk=";
          };
          dependencies = with pythonPackages; [
            azure-mgmt-core
            isodate
            typing-extensions
          ];
        });
        pythonEnv = python.withPackages (
          ps: with ps; [
            azureAiProjects
            azure-core
            azure-identity
            azureMgmtCognitiveServices
            azure-mgmt-core
            azureMgmtStorage
            azureMgmtWeb
            platformdirs
            pydantic
            pyinstaller
            rich
            typer
          ]
        );

        packageSource = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            (pkgs.lib.fileset.fileFilter (file: file.hasExt "py" || file.name == "py.typed") ./azurator)
            (pkgs.lib.fileset.fileFilter (file: file.hasExt "py") ./tests)
            ./.github/workflows/pyinstaller.yml
            ./LICENSE
            ./README.md
            ./pyproject.toml
          ];
        };

        cacheSetup = ''
          if [ -n "''${XDG_CACHE_HOME:-}" ]; then
            export AZURATOR_CACHE_ROOT="$XDG_CACHE_HOME/azurator"
          else
            export AZURATOR_CACHE_ROOT="$HOME/.cache/azurator"
          fi

          export PNPM_HOME="$AZURATOR_CACHE_ROOT/pnpm-home"
          export AZURATOR_PNPM_STORE_DIR="$AZURATOR_CACHE_ROOT/pnpm-store"
          export AZURATOR_DOCS_VIRTUAL_STORE_DIR="$AZURATOR_CACHE_ROOT/docs-virtual-store"
          mkdir -p \
            "$PNPM_HOME" \
            "$AZURATOR_PNPM_STORE_DIR" \
            "$AZURATOR_DOCS_VIRTUAL_STORE_DIR"
          export PATH="$PNPM_HOME:$PATH"
        '';

        docsDependencies = ''
          pnpm --dir docs install \
            --store-dir "$AZURATOR_PNPM_STORE_DIR" \
            --virtual-store-dir "$AZURATOR_DOCS_VIRTUAL_STORE_DIR" \
            --frozen-lockfile
        '';

        azurator = pythonPackages.buildPythonPackage {
          inherit pname version;
          pyproject = true;
          src = packageSource;

          build-system = with pythonPackages; [
            setuptools
          ];

          dependencies = with pythonPackages; [
            azureAiProjects
            azure-core
            azure-identity
            azureMgmtCognitiveServices
            azure-mgmt-core
            azureMgmtStorage
            azureMgmtWeb
            platformdirs
            pydantic
            rich
            typer
          ];

          makeWrapperArgs = [
            "--prefix"
            "PATH"
            ":"
            (pkgs.lib.makeBinPath [ pkgs.sops ])
          ];

          nativeCheckInputs = with pythonPackages; [
            pytestCheckHook
          ];

          pythonImportsCheck = [
            "azurator"
          ];

          meta = with pkgs.lib; {
            description = project.project.description;
            homepage = project.project.urls.homepage;
            license = licenses.mit;
            mainProgram = "azurator";
            platforms = platforms.unix ++ platforms.windows;
          };
        };

        docs-install = pkgs.writeShellApplication {
          name = "azurator-docs-install";
          runtimeInputs = [
            pkgs.nodejs_24
            pkgs.pnpm
          ];
          text = ''
            ${cacheSetup}
            ${docsDependencies}
          '';
        };

        docs-build = pkgs.writeShellApplication {
          name = "azurator-docs-build";
          runtimeInputs = [
            pkgs.nodejs_24
            pkgs.pnpm
          ];
          text = ''
            ${cacheSetup}
            if [ ! -d docs/node_modules ] || [ ! -f "$AZURATOR_DOCS_VIRTUAL_STORE_DIR/lock.yaml" ]; then
              ${docsDependencies}
            fi
            pnpm --dir docs build
          '';
        };

        docs-check = pkgs.writeShellApplication {
          name = "azurator-docs-check";
          runtimeInputs = [
            pkgs.nodejs_24
            pkgs.pnpm
          ];
          text = ''
            ${cacheSetup}
            if [ ! -d docs/node_modules ] || [ ! -f "$AZURATOR_DOCS_VIRTUAL_STORE_DIR/lock.yaml" ]; then
              ${docsDependencies}
            fi
            pnpm --dir docs check
          '';
        };

        docs-dev = pkgs.writeShellApplication {
          name = "azurator-docs-dev";
          runtimeInputs = [
            pkgs.nodejs_24
            pkgs.pnpm
          ];
          text = ''
            ${cacheSetup}
            if [ ! -d docs/node_modules ] || [ ! -f "$AZURATOR_DOCS_VIRTUAL_STORE_DIR/lock.yaml" ]; then
              ${docsDependencies}
            fi
            pnpm --dir docs dev
          '';
        };

        liveTestInfra = ./infra/live-test;

        liveTestBicepCheck =
          pkgs.runCommand "azurator-live-test-bicep"
            {
              nativeBuildInputs = [
                pkgs.bicep
              ];
            }
            ''
              mkdir -p "$out"
              export DOTNET_BUNDLE_EXTRACT_BASE_DIR="$TMPDIR/dotnet-bundle"
              mkdir -p "$DOTNET_BUNDLE_EXTRACT_BASE_DIR"
              bicep build ${liveTestInfra}/main.bicep --outfile "$out/main.json"
              bicep build ${liveTestInfra}/resources.bicep --outfile "$out/resources.json"
              bicep build-params ${liveTestInfra}/live-test.bicepparam --outfile "$out/parameters.json"
            '';

        liveTestLifecycleCheck =
          pkgs.runCommand "azurator-live-test-lifecycle"
            {
              nativeBuildInputs = [
                pkgs.shellcheck
              ];
            }
            ''
              shellcheck ${liveTestInfra}/lifecycle.sh
              shellcheck ${liveTestInfra}/scope.sh ${liveTestInfra}/scope_test.sh
              bash ${liveTestInfra}/scope_test.sh
              touch "$out"
            '';

        liveTestE2ECheck =
          pkgs.runCommand "azurator-live-test-e2e"
            {
              nativeBuildInputs = [
                pkgs.age
                pkgs.bash
                pkgs.coreutils
                pkgs.jq
                pkgs.shellcheck
                pkgs.sops
              ];
            }
            ''
              shellcheck \
                ${liveTestInfra}/e2e.sh \
                ${liveTestInfra}/e2e_test.sh \
                ${liveTestInfra}/e2e_test_driver.sh
              bash ${liveTestInfra}/e2e_test.sh
              touch "$out"
            '';

        liveTestRecoveryCheck =
          pkgs.runCommand "azurator-live-test-recovery"
            {
              nativeBuildInputs = [
                pkgs.bash
                pkgs.coreutils
                pkgs.jq
                pkgs.shellcheck
              ];
            }
            ''
              shellcheck \
                ${liveTestInfra}/recovery.sh \
                ${liveTestInfra}/recovery_test.sh \
                ${liveTestInfra}/recovery_test_driver.sh
              bash ${liveTestInfra}/recovery_test.sh
              touch "$out"
            '';

        workflowLintCheck =
          pkgs.runCommand "azurator-workflow-lint"
            {
              nativeBuildInputs = [
                pkgs.actionlint
                pkgs.shellcheck
              ];
            }
            ''
              actionlint \
                ${./.github/workflows/docs.yml} \
                ${./.github/workflows/pyinstaller.yml} \
                ${./.github/workflows/release.yml} \
                ${./.github/workflows/test.yml}
              touch "$out"
            '';

        knowledgeSource = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            ./.github/scripts/check_knowledge.py
            ./AGENTS.md
            ./CONTRIBUTING.md
            ./LICENSE
            ./README.md
            ./infra/live-test/README.md
            ./knowledge
          ];
        };

        knowledgeCheck =
          pkgs.runCommand "azurator-knowledge-check"
            {
              nativeBuildInputs = [ pkgs.python3 ];
            }
            ''
              cd ${knowledgeSource}
              python .github/scripts/check_knowledge.py
              touch "$out"
            '';

        packageSourceBoundaryCheck = pkgs.runCommand "azurator-package-source-boundary" { } ''
          test -f ${packageSource}/azurator/__init__.py
          test -f ${packageSource}/azurator/composition.py
          test -f ${packageSource}/azurator/presentation.py
          test -f ${packageSource}/azurator/workflows.py
          test ! -e ${packageSource}/azurator/providers/fake.py
          test -f ${packageSource}/tests/test_operation.py
          test -f ${packageSource}/.github/workflows/pyinstaller.yml
          test -f ${packageSource}/pyproject.toml
          test ! -e ${packageSource}/plan.json
          test ! -e ${packageSource}/.env
          test ! -e ${packageSource}/.venv
          test ! -e ${packageSource}/.coverage
          test ! -e ${packageSource}/.pytest_cache
          test ! -e ${packageSource}/.ruff_cache
          test ! -e ${packageSource}/docs
          test ! -e ${packageSource}/dist
          test ! -e ${packageSource}/azurator/__pycache__
          test ! -e ${packageSource}/tests/__pycache__
          touch "$out"
        '';

        mkLiveTestApp =
          command:
          pkgs.writeShellApplication {
            name = "azurator-live-test-${command}";
            runtimeInputs = [
              pkgs.azure-cli
              pkgs.bicep
              pkgs.coreutils
              pkgs.jq
            ];
            text = ''
              export AZURATOR_LIVE_TEST_TEMPLATE="${liveTestInfra}/main.bicep"
              export AZURATOR_LIVE_TEST_RESOURCES="${liveTestInfra}/resources.bicep"
              export AZURATOR_LIVE_TEST_PARAMETERS="${liveTestInfra}/live-test.bicepparam"
              export AZURATOR_LIVE_TEST_SCOPE_FILE="$PWD/infra/live-test/.env"
              exec ${pkgs.bash}/bin/bash "${liveTestInfra}/lifecycle.sh" ${command} "$@"
            '';
          };

        live-test-what-if = mkLiveTestApp "what-if";
        live-test-up = mkLiveTestApp "up";
        live-test-down = mkLiveTestApp "down";
        live-test-e2e = pkgs.writeShellApplication {
          name = "azurator-live-test-e2e";
          runtimeInputs = [
            azurator
            pkgs.age
            pkgs.azure-cli
            pkgs.bash
            pkgs.bicep
            pkgs.coreutils
            pkgs.jq
            pkgs.sops
          ];
          text = ''
            export AZURATOR_LIVE_TEST_TEMPLATE="${liveTestInfra}/main.bicep"
            export AZURATOR_LIVE_TEST_RESOURCES="${liveTestInfra}/resources.bicep"
            export AZURATOR_LIVE_TEST_PARAMETERS="${liveTestInfra}/live-test.bicepparam"
            export AZURATOR_LIVE_TEST_BASH="${pkgs.bash}/bin/bash"
            export AZURATOR_LIVE_TEST_AZ="${pkgs.azure-cli}/bin/az"
            export AZURATOR_LIVE_TEST_AGE_KEYGEN="${pkgs.age}/bin/age-keygen"
            export AZURATOR_LIVE_TEST_JQ="${pkgs.jq}/bin/jq"
            export AZURATOR_LIVE_TEST_SOPS="${pkgs.sops}/bin/sops"
            export AZURATOR_LIVE_TEST_AZURATOR="${azurator}/bin/azurator"
            export AZURATOR_LIVE_TEST_LIFECYCLE="${liveTestInfra}/lifecycle.sh"
            export AZURATOR_LIVE_TEST_SCOPE_FILE="$PWD/infra/live-test/.env"
            exec ${pkgs.bash}/bin/bash "${liveTestInfra}/e2e.sh" "$@"
          '';
        };
        live-test-recovery = pkgs.writeShellApplication {
          name = "azurator-live-test-recovery";
          runtimeInputs = [
            azurator
            pkgs.azure-cli
            pkgs.bash
            pkgs.bicep
            pkgs.coreutils
            pkgs.jq
          ];
          text = ''
            export AZURATOR_LIVE_TEST_TEMPLATE="${liveTestInfra}/main.bicep"
            export AZURATOR_LIVE_TEST_RESOURCES="${liveTestInfra}/resources.bicep"
            export AZURATOR_LIVE_TEST_PARAMETERS="${liveTestInfra}/live-test.bicepparam"
            export AZURATOR_LIVE_TEST_BASH="${pkgs.bash}/bin/bash"
            export AZURATOR_LIVE_TEST_AZ="${pkgs.azure-cli}/bin/az"
            export AZURATOR_LIVE_TEST_JQ="${pkgs.jq}/bin/jq"
            export AZURATOR_LIVE_TEST_AZURATOR="${azurator}/bin/azurator"
            export AZURATOR_LIVE_TEST_LIFECYCLE="${liveTestInfra}/lifecycle.sh"
            export AZURATOR_LIVE_TEST_SCOPE_FILE="$PWD/infra/live-test/.env"
            exec ${pkgs.bash}/bin/bash "${liveTestInfra}/recovery.sh" "$@"
          '';
        };

        mkFlakeApp = program: description: {
          type = "app";
          inherit program;
          meta = { inherit description; };
        };
      in
      {
        packages = {
          default = azurator;
          inherit azurator;
        };

        checks = {
          package = azurator;
          live-test-bicep = liveTestBicepCheck;
          live-test-e2e = liveTestE2ECheck;
          live-test-lifecycle = liveTestLifecycleCheck;
          live-test-recovery = liveTestRecoveryCheck;
          workflow-lint = workflowLintCheck;
          knowledge = knowledgeCheck;
          package-source-boundary = packageSourceBoundaryCheck;
        };

        apps = {
          docs-install = mkFlakeApp "${docs-install}/bin/azurator-docs-install" "Install the pinned documentation dependencies";
          docs-build = mkFlakeApp "${docs-build}/bin/azurator-docs-build" "Build the Starlight documentation site";
          docs-check = mkFlakeApp "${docs-check}/bin/azurator-docs-check" "Check the Starlight documentation site";
          docs-dev = mkFlakeApp "${docs-dev}/bin/azurator-docs-dev" "Run the local Starlight development server";
          live-test-what-if = mkFlakeApp "${live-test-what-if}/bin/azurator-live-test-what-if" "Preview the disposable Azure live-test fixture";
          live-test-up = mkFlakeApp "${live-test-up}/bin/azurator-live-test-up" "Deploy the disposable Azure live-test fixture";
          live-test-down = mkFlakeApp "${live-test-down}/bin/azurator-live-test-down" "Delete the disposable Azure live-test fixture";
          live-test-e2e = mkFlakeApp "${live-test-e2e}/bin/azurator-live-test-e2e" "Run the guided disposable Azure end-to-end test";
          live-test-recovery = mkFlakeApp "${live-test-recovery}/bin/azurator-live-test-recovery" "Run the guided disposable Azure recovery test";
        };

        formatter = pkgs.nixfmt;

        devShells.default = pkgs.mkShell {
          packages = [
            pythonEnv
            pkgs.age
            pkgs.azure-cli
            pkgs.bicep
            pkgs.jq
            pkgs.nodejs_24
            pkgs.pnpm
            pkgs.pyright
            pkgs.ruff
            pkgs.sops
            pkgs.uv
          ];

          shellHook = ''
            unset PYTHONPATH
            ${cacheSetup}
            export UV_PROJECT_ENVIRONMENT="$AZURATOR_CACHE_ROOT/venv"
            if [ ! -e "$PWD/.venv" ] && [ ! -L "$PWD/.venv" ]; then
              ln -s "$UV_PROJECT_ENVIRONMENT" "$PWD/.venv"
            fi
          '';
        };
      }
    );
}
