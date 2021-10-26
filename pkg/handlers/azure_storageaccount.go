// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// ------------------------------------------------------------

package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/to"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2021-04-01/storage"
	"github.com/Azure/radius/pkg/azure/armauth"
	"github.com/Azure/radius/pkg/azure/azresources"
	"github.com/Azure/radius/pkg/azure/clients"
	"github.com/Azure/radius/pkg/keys"
	"github.com/Azure/radius/pkg/radlogger"
	"github.com/gofrs/uuid"
)

func getStorageAccountByID(ctx context.Context, arm armauth.ArmConfig, accountID string) (*storage.Account, error) {
	parsed, err := azresources.Parse(accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Storage Account resource id: %w", err)
	}

	sac := clients.NewAccountsClient(parsed.SubscriptionID, arm.Auth)

	account, err := sac.GetProperties(ctx, parsed.ResourceGroup, parsed.Types[0].Name, storage.AccountExpand(""))
	if err != nil {
		return nil, fmt.Errorf("failed to get Storage Account: %w", err)
	}

	return &account, nil
}

func deleteStorageAccount(ctx context.Context, arm armauth.ArmConfig, accountName string) error {
	sc := clients.NewAccountsClient(arm.SubscriptionID, arm.Auth)

	_, err := sc.Delete(ctx, arm.ResourceGroup, accountName)
	if err != nil {
		return fmt.Errorf("failed to delete storage account: %w", err)
	}
	return nil
}

func createStorageAccount(ctx context.Context, arm armauth.ArmConfig, accountName string, options PutOptions) (*storage.Account, error) {
	location, err := clients.GetResourceGroupLocation(ctx, arm)
	if err != nil {
		return nil, err
	}

	sc := clients.NewAccountsClient(arm.SubscriptionID, arm.Auth)

	future, err := sc.Create(ctx, arm.ResourceGroup, accountName, storage.AccountCreateParameters{
		Location: location,
		Tags:     keys.MakeTagsForRadiusResource(options.ApplicationName, options.ResourceName),
		Kind:     storage.KindStorageV2,
		Sku: &storage.Sku{
			Name: storage.SkuNameStandardLRS,
		},
		AccountPropertiesCreateParameters: &storage.AccountPropertiesCreateParameters{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create/update storage account: %w", err)
	}

	err = future.WaitForCompletionRef(ctx, sc.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to create/update storage account: %w", err)
	}

	account, err := future.Result(sc)
	if err != nil {
		return nil, fmt.Errorf("failed to create/update storage account: %w", err)
	}

	return &account, nil
}

func generateStorageAccountName(ctx context.Context, arm armauth.ArmConfig, baseName string) (*string, error) {
	logger := radlogger.GetLogger(ctx)
	sc := clients.NewAccountsClient(arm.SubscriptionID, arm.Auth)

	// names are kinda finicky here - they have to be unique across azure.
	name := ""

	for i := 0; i < 10; i++ {
		// 3-24 characters - all alphanumeric
		uid, err := uuid.NewV4()
		if err != nil {
			return nil, fmt.Errorf("failed to generate storage account name: %w", err)
		}
		name = baseName + strings.ReplaceAll(uid.String(), "-", "")
		name = name[0:24]

		result, err := sc.CheckNameAvailability(ctx, storage.AccountCheckNameAvailabilityParameters{
			Name: to.StringPtr(name),
			Type: to.StringPtr(azresources.StorageStorageAccounts),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to query storage account name: %w", err)
		}

		if result.NameAvailable != nil && *result.NameAvailable {
			return &name, nil
		}

		logger.Info(fmt.Sprintf("storage account name generation failed: %v %v", result.Reason, result.Message))
	}

	return nil, fmt.Errorf("failed to find a storage account name")
}