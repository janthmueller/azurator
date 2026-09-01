targetScope = 'subscription'

@description('Dedicated lifecycle boundary for the disposable Azurator live-test resources.')
param resourceGroupName string

@description('Azure region used by every resource in the disposable live-test environment.')
param location string

@description('Run-specific suffix for globally unique Azure resource names.')
@minLength(8)
@maxLength(8)
param nameSuffix string = substring(uniqueString(subscription().id, deployment().name), 0, 8)

var fixtureTags = {
  'azurator-fixture': 'live-test'
  'azurator-owner': 'azurator-repository'
  'azurator-ephemeral': 'true'
}

resource testResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: resourceGroupName
  location: location
  tags: fixtureTags
}

module resources './resources.bicep' = {
  name: 'azurator-live-test-resources'
  scope: testResourceGroup
  params: {
    location: location
    nameSuffix: nameSuffix
    tags: fixtureTags
  }
}

output resourceGroupName string = testResourceGroup.name
output storageAccountName string = resources.outputs.storageAccountName
output disabledStorageAccountName string = resources.outputs.disabledStorageAccountName
output foundryAccountName string = resources.outputs.foundryAccountName
output disabledFoundryAccountName string = resources.outputs.disabledFoundryAccountName
output foundryProjectName string = resources.outputs.foundryProjectName
output openAiAccountName string = resources.outputs.openAiAccountName
output appServiceName string = resources.outputs.appServiceName
output connectionNames array = resources.outputs.connectionNames
