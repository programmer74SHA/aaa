package mapper

import (
	"strings"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// SwitchMetadataDomain2Storage converts domain switch metadata to storage model
func SwitchMetadataDomain2Storage(domainMetadata *domain.SwitchMetadata) *types.SwitchMetadata {
	if domainMetadata == nil {
		return nil
	}

	return &types.SwitchMetadata{
		ID:        domainMetadata.ID,
		ScannerID: domainMetadata.ScannerID,
		AssetID:   domainMetadata.AssetID,
		Username:  domainMetadata.Username,
		Password:  domainMetadata.Password,
		Port:      domainMetadata.Port,
		Brand:     domainMetadata.Brand,
	}
}

// SwitchMetadataStorage2Domain converts storage switch metadata to domain model
func SwitchMetadataStorage2Domain(storageMetadata *types.SwitchMetadata) *domain.SwitchMetadata {
	if storageMetadata == nil {
		return nil
	}

	return &domain.SwitchMetadata{
		ID:        storageMetadata.ID,
		AssetID:   storageMetadata.AssetID,
		ScannerID: storageMetadata.ScannerID,
		Username:  storageMetadata.Username,
		Password:  storageMetadata.Password,
		Port:      storageMetadata.Port,
		Brand:     storageMetadata.Brand,
	}
}

// SwitchNeighborDomain2Storage converts domain switch neighbor to storage model
func SwitchNeighborDomain2Storage(domainNeighbor *domain.SwitchNeighbor, switchID string) *types.SwitchNeighbor {
	if domainNeighbor == nil {
		return nil
	}

	var capabilities *string
	if len(domainNeighbor.Capabilities) > 0 {
		capStr := strings.Join(domainNeighbor.Capabilities, ",")
		capabilities = &capStr
	}

	return &types.SwitchNeighbor{
		SwitchID:     switchID,
		DeviceID:     domainNeighbor.DeviceID,
		LocalPort:    domainNeighbor.LocalPort,
		RemotePort:   stringPtrOrEmpty(domainNeighbor.RemotePort),
		Platform:     stringPtrOrEmpty(domainNeighbor.Platform),
		IPAddress:    stringPtrOrEmpty(domainNeighbor.IPAddress),
		Capabilities: capabilities,
		Software:     stringPtrOrEmpty(domainNeighbor.Software),
		Duplex:       stringPtrOrEmpty(domainNeighbor.Duplex),
		Protocol:     domainNeighbor.Protocol,
	}
}

// SwitchNeighborStorage2Domain converts storage switch neighbor to domain model
func SwitchNeighborStorage2Domain(storageNeighbor *types.SwitchNeighbor) *domain.SwitchNeighbor {
	if storageNeighbor == nil {
		return nil
	}

	var capabilities []string
	if storageNeighbor.Capabilities != nil && *storageNeighbor.Capabilities != "" {
		capabilities = strings.Split(*storageNeighbor.Capabilities, ",")
	}

	return &domain.SwitchNeighbor{
		DeviceID:     storageNeighbor.DeviceID,
		LocalPort:    storageNeighbor.LocalPort,
		RemotePort:   stringValueOrEmpty(storageNeighbor.RemotePort),
		Platform:     stringValueOrEmpty(storageNeighbor.Platform),
		IPAddress:    stringValueOrEmpty(storageNeighbor.IPAddress),
		Capabilities: capabilities,
		Software:     stringValueOrEmpty(storageNeighbor.Software),
		Duplex:       stringValueOrEmpty(storageNeighbor.Duplex),
		Protocol:     storageNeighbor.Protocol,
	}
}

// Helper functions
func stringPtrOrEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func stringValueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
