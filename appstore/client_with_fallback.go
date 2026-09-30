package appstore

import (
	"context"
	"errors"
)

var ErrNoClients = errors.New("appstore: no clients")

type AppStoreClientWithFallback struct {
	Clients []AppleAppStoreClient
}

func (s AppStoreClientWithFallback) GetAllSubscriptionStatuses(ctx context.Context, originalTransactionID TransactionID) (status *StatusResponse, err error) {
	if len(s.Clients) == 0 {
		return nil, ErrNoClients
	}

	for _, client := range s.Clients {
		status, err = client.GetAllSubscriptionStatuses(ctx, originalTransactionID)
		if err == nil {
			return status, nil
		}
	}
	return nil, err
}

func (s AppStoreClientWithFallback) GetTransactionInfo(ctx context.Context, transactionID TransactionID) (info *TransactionInfo, err error) {
	if len(s.Clients) == 0 {
		return nil, ErrNoClients
	}

	for _, client := range s.Clients {
		info, err = client.GetTransactionInfo(ctx, transactionID)
		if err == nil {
			return info, nil
		}
	}
	return nil, err
}

func (s AppStoreClientWithFallback) SendConsumptionInformation(ctx context.Context, transactionID TransactionID, req ConsumptionRequest) (err error) {
	if len(s.Clients) == 0 {
		return ErrNoClients
	}

	for _, client := range s.Clients {
		if err = client.SendConsumptionInformation(ctx, transactionID, req); err == nil {
			return nil
		}
	}
	return err
}
