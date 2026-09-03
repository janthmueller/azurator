targetScope = 'resourceGroup'

@description('Azure region used by every resource in the disposable live-test environment.')
param location string = resourceGroup().location

@description('Run-specific suffix for globally unique Azure resource names.')
@minLength(8)
@maxLength(8)
param nameSuffix string = substring(uniqueString(subscription().id, deployment().name), 0, 8)

@description('Non-secret ownership and lifecycle tags inherited from the test resource group.')
param tags object = resourceGroup().tags

var storageAccountName = 'stazurator${nameSuffix}'
var disabledStorageAccountName = 'stazuratordis${nameSuffix}'
var foundryAccountName = 'ai-azurator-${nameSuffix}'
var disabledFoundryAccountName = 'ai-azurator-disabled-${nameSuffix}'
var foundryProjectName = 'project-azurator-${nameSuffix}'
var openAiAccountName = 'aoai-azurator-${nameSuffix}'
var storageConnectionName = 'storage-key1'
var openAiConnectionName = 'openai-key1'
var appServicePlanName = 'plan-azurator-${nameSuffix}'
var appServiceName = 'app-azurator-${nameSuffix}'
var rotationStorageTags = union(tags, {
  'azurator-live-test-role': 'rotation-storage'
})
var disabledStorageTags = union(tags, {
  'azurator-live-test-role': 'disabled-storage'
})
var foundryProjectHostTags = union(tags, {
  'azurator-live-test-role': 'foundry-project-host'
})
var disabledFoundryTags = union(tags, {
  'azurator-live-test-role': 'disabled-foundry'
})
var rotationOpenAiTags = union(tags, {
  'azurator-live-test-role': 'rotation-openai'
})
var appServiceBindingTags = union(tags, {
  'azurator-live-test-role': 'app-service-settings'
})
var foundryUserRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '53ca6127-db72-4b80-b1b0-d745d6d5456d'
)
var storageTarget = 'https://${storageAccountName}.blob.${environment().suffixes.storage}/'

// Azurator's reviewed Foundry provider is intentionally scoped to Azure public cloud.
#disable-next-line no-hardcoded-env-urls
var openAiTarget = 'https://${openAiAccountName}.openai.azure.com/'

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageAccountName
  location: location
  tags: rotationStorageTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: true
    defaultToOAuthAuthentication: false
    isHnsEnabled: false
    isNfsV3Enabled: false
    isSftpEnabled: false
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Allow'
    }
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource disabledStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: disabledStorageAccountName
  location: location
  tags: disabledStorageTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    isHnsEnabled: false
    isNfsV3Enabled: false
    isSftpEnabled: false
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Allow'
    }
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource foundryAccount 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: foundryAccountName
  location: location
  tags: foundryProjectHostTags
  identity: {
    type: 'SystemAssigned'
  }
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  properties: {
    allowProjectManagement: true
    customSubDomainName: foundryAccountName
    disableLocalAuth: false
    dynamicThrottlingEnabled: false
    publicNetworkAccess: 'Enabled'
    restrictOutboundNetworkAccess: false
  }
}

resource disabledFoundryAccount 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: disabledFoundryAccountName
  location: location
  tags: disabledFoundryTags
  identity: {
    type: 'SystemAssigned'
  }
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  properties: {
    allowProjectManagement: true
    customSubDomainName: disabledFoundryAccountName
    disableLocalAuth: true
    dynamicThrottlingEnabled: false
    publicNetworkAccess: 'Enabled'
    restrictOutboundNetworkAccess: false
  }
}

resource foundryProject 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = {
  parent: foundryAccount
  name: foundryProjectName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    description: 'Disposable Azurator live-test project. Contains no model deployment or workload.'
    displayName: 'Azurator live test'
  }
}

// Owner and Contributor grant Foundry control-plane permissions but not its
// data actions. Scope the least-privilege built-in Foundry User role to this
// disposable account so the same principal running Azurator can inspect and
// verify its project connections.
resource fixtureOperatorFoundryUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(foundryAccount.id, deployer().objectId, foundryUserRoleDefinitionId)
  scope: foundryAccount
  properties: {
    principalId: deployer().objectId
    roleDefinitionId: foundryUserRoleDefinitionId
  }
}

resource openAiAccount 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: openAiAccountName
  location: location
  tags: rotationOpenAiTags
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: openAiAccountName
    disableLocalAuth: false
    dynamicThrottlingEnabled: false
    publicNetworkAccess: 'Enabled'
    restrictOutboundNetworkAccess: false
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: appServicePlanName
  location: location
  tags: appServiceBindingTags
  kind: 'linux'
  sku: {
    name: 'F1'
    tier: 'Free'
    size: 'F1'
    family: 'F'
    capacity: 1
  }
  properties: {
    reserved: true
    zoneRedundant: false
  }
}

resource appService 'Microsoft.Web/sites@2024-11-01' = {
  name: appServiceName
  location: location
  tags: appServiceBindingTags
  kind: 'app,linux'
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        {
          name: 'AZURATOR_STORAGE_KEY'
          value: storageAccount.listKeys().keys[0].value
        }
        {
          name: 'AZURATOR_STORAGE_ALIAS'
          value: storageAccount.listKeys().keys[0].value
        }
        {
          name: 'AZURATOR_STORAGE_CONNECTION'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=core.windows.net'
        }
        {
          name: 'AZURATOR_OPENAI_KEY'
          value: openAiAccount.listKeys().key1
        }
        {
          name: 'AZURATOR_UNRELATED'
          value: 'preserve-me'
        }
      ]
    }
  }
}

// Azure's published 2025-06-01 ARM schema documents AccountKey credentials but
// omits the AzureStorageAccount category returned by the public-cloud service.
// This fixture emits only Azurator's reviewed observed category/credential pair.
resource storageConnection 'Microsoft.CognitiveServices/accounts/projects/connections@2025-06-01' = {
  parent: foundryProject
  name: storageConnectionName
  properties: any({
    authType: 'AccountKey'
    category: 'AzureStorageAccount'
    credentials: {
      key: storageAccount.listKeys().keys[0].value
    }
    isSharedToAll: false
    metadata: {
      ApiType: 'Azure'
      ResourceId: storageAccount.id
      location: location
    }
    peRequirement: 'NotApplicable'
    peStatus: 'NotApplicable'
    target: storageTarget
    useWorkspaceManagedIdentity: false
  })
}

resource openAiConnection 'Microsoft.CognitiveServices/accounts/projects/connections@2025-06-01' = {
  parent: foundryProject
  name: openAiConnectionName
  properties: {
    authType: 'ApiKey'
    category: 'AzureOpenAI'
    credentials: {
      key: openAiAccount.listKeys().key1
    }
    isSharedToAll: false
    metadata: {
      ApiType: 'Azure'
      ResourceId: openAiAccount.id
      location: location
    }
    peRequirement: 'NotApplicable'
    peStatus: 'NotApplicable'
    target: openAiTarget
    useWorkspaceManagedIdentity: false
  }
}

output storageAccountName string = storageAccount.name
output disabledStorageAccountName string = disabledStorageAccount.name
output foundryAccountName string = foundryAccount.name
output disabledFoundryAccountName string = disabledFoundryAccount.name
output foundryProjectName string = foundryProject.name
output openAiAccountName string = openAiAccount.name
output appServiceName string = appService.name
output connectionNames array = [
  storageConnection.name
  openAiConnection.name
]
