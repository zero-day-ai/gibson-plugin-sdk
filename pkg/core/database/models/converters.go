// Package models provides conversion functions between core and database models
package models

import (
	"encoding/json"
	"time"

	coremodels "github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/google/uuid"
)

// ConvertPluginInfoToDatabase converts core PluginInfo to database model
func ConvertPluginInfoToDatabase(core *coremodels.PluginInfo) (*PluginInfoDB, error) {
	if core == nil {
		return nil, nil
	}

	db := &PluginInfoDB{
		ID:         core.ID,
		Name:       core.Name,
		Version:    core.Version,
		Author:     core.Author,
		SDKVersion: core.SDKVersion,
		CreatedAt:  core.CreatedAt,
		UpdatedAt:  core.UpdatedAt,
	}

	// Handle nullable fields
	if core.Description != "" {
		db.Description = &core.Description
	}

	// Convert domains to JSON string
	if len(core.Domains) > 0 {
		domainsJSON, err := json.Marshal(core.Domains)
		if err != nil {
			return nil, err
		}
		domainsStr := string(domainsJSON)
		db.Domains = &domainsStr
	}

	// Convert capabilities to JSON string
	if len(core.Capabilities) > 0 {
		capabilitiesJSON, err := json.Marshal(core.Capabilities)
		if err != nil {
			return nil, err
		}
		capabilitiesStr := string(capabilitiesJSON)
		db.Capabilities = &capabilitiesStr
	}

	// Convert config to JSON string
	if len(core.Config) > 0 {
		configJSON, err := json.Marshal(core.Config)
		if err != nil {
			return nil, err
		}
		configStr := string(configJSON)
		db.Config = &configStr
	}

	return db, nil
}

// ConvertPluginInfoFromDatabase converts database PluginInfo to core model
func ConvertPluginInfoFromDatabase(db *PluginInfoDB) (*coremodels.PluginInfo, error) {
	if db == nil {
		return nil, nil
	}

	core := &coremodels.PluginInfo{
		ID:         db.ID,
		Name:       db.Name,
		Version:    db.Version,
		Author:     db.Author,
		SDKVersion: db.SDKVersion,
		CreatedAt:  db.CreatedAt,
		UpdatedAt:  db.UpdatedAt,
	}

	// Handle nullable fields
	if db.Description != nil {
		core.Description = *db.Description
	}

	// Convert domains from JSON string
	if db.Domains != nil {
		var domains []coremodels.SecurityDomain
		if err := json.Unmarshal([]byte(*db.Domains), &domains); err != nil {
			return nil, err
		}
		core.Domains = domains
	}

	// Convert capabilities from JSON string
	if db.Capabilities != nil {
		var capabilities []string
		if err := json.Unmarshal([]byte(*db.Capabilities), &capabilities); err != nil {
			return nil, err
		}
		core.Capabilities = capabilities
	}

	// Convert config from JSON string
	if db.Config != nil {
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(*db.Config), &config); err != nil {
			return nil, err
		}
		core.Config = config
	}

	// Initialize empty maps/slices if nil
	if core.Config == nil {
		core.Config = make(map[string]interface{})
	}
	if core.Capabilities == nil {
		core.Capabilities = []string{}
	}
	if core.Domains == nil {
		core.Domains = []coremodels.SecurityDomain{}
	}

	return core, nil
}

// ConvertTargetToDatabase converts core Target to database model
func ConvertTargetToDatabase(core *coremodels.Target) (*TargetDB, error) {
	if core == nil {
		return nil, nil
	}

	db := &TargetDB{
		ID:        core.ID,
		Name:      core.Name,
		Type:      string(core.Type),
		CreatedAt: core.CreatedAt,
		UpdatedAt: core.UpdatedAt,
	}

	// Handle nullable fields
	if core.URL != "" {
		db.URL = &core.URL
	}

	// Convert credentials to JSON string
	if len(core.Credentials) > 0 {
		credentialsJSON, err := json.Marshal(core.Credentials)
		if err != nil {
			return nil, err
		}
		credentialsStr := string(credentialsJSON)
		db.Credentials = &credentialsStr
	}

	// Convert config to JSON string
	if len(core.Config) > 0 {
		configJSON, err := json.Marshal(core.Config)
		if err != nil {
			return nil, err
		}
		configStr := string(configJSON)
		db.Config = &configStr
	}

	// Convert tags to JSON string
	if len(core.Tags) > 0 {
		tagsJSON, err := json.Marshal(core.Tags)
		if err != nil {
			return nil, err
		}
		tagsStr := string(tagsJSON)
		db.Tags = &tagsStr
	}

	return db, nil
}

// ConvertTargetFromDatabase converts database Target to core model
func ConvertTargetFromDatabase(db *TargetDB) (*coremodels.Target, error) {
	if db == nil {
		return nil, nil
	}

	core := &coremodels.Target{
		ID:        db.ID,
		Name:      db.Name,
		Type:      coremodels.TargetType(db.Type),
		CreatedAt: db.CreatedAt,
		UpdatedAt: db.UpdatedAt,
	}

	// Handle nullable fields
	if db.URL != nil {
		core.URL = *db.URL
	}

	// Convert credentials from JSON string
	if db.Credentials != nil {
		var credentials map[string]string
		if err := json.Unmarshal([]byte(*db.Credentials), &credentials); err != nil {
			return nil, err
		}
		core.Credentials = credentials
	}

	// Convert config from JSON string
	if db.Config != nil {
		var config map[string]string
		if err := json.Unmarshal([]byte(*db.Config), &config); err != nil {
			return nil, err
		}
		core.Config = config
	}

	// Convert tags from JSON string
	if db.Tags != nil {
		var tags []string
		if err := json.Unmarshal([]byte(*db.Tags), &tags); err != nil {
			return nil, err
		}
		core.Tags = tags
	}

	// Initialize empty maps/slices if nil
	if core.Credentials == nil {
		core.Credentials = make(map[string]string)
	}
	if core.Config == nil {
		core.Config = make(map[string]string)
	}
	if core.Tags == nil {
		core.Tags = []string{}
	}

	return core, nil
}

// ConvertAssessRequestToDatabase converts core AssessRequest to database model
func ConvertAssessRequestToDatabase(core *coremodels.AssessRequest) (*AssessRequestDB, error) {
	if core == nil {
		return nil, nil
	}

	db := &AssessRequestDB{
		ID:         core.ID,
		TargetID:   core.Target.ID,
		ScanID:     core.ScanID,
		Timeout:    int64(core.Timeout),
		RequestID:  core.RequestID,
		Timestamp:  core.Timestamp,
		Priority:   string(core.Priority),
		RetryCount: core.RetryCount,
	}

	// Convert config to JSON string
	if len(core.Config) > 0 {
		configJSON, err := json.Marshal(core.Config)
		if err != nil {
			return nil, err
		}
		configStr := string(configJSON)
		db.Config = &configStr
	}

	// Convert metadata to JSON string
	if len(core.Metadata) > 0 {
		metadataJSON, err := json.Marshal(core.Metadata)
		if err != nil {
			return nil, err
		}
		metadataStr := string(metadataJSON)
		db.Metadata = &metadataStr
	}

	return db, nil
}

// ConvertAssessRequestFromDatabase converts database AssessRequest to core model
func ConvertAssessRequestFromDatabase(db *AssessRequestDB, target *coremodels.Target) (*coremodels.AssessRequest, error) {
	if db == nil {
		return nil, nil
	}

	core := &coremodels.AssessRequest{
		ID:         db.ID,
		Target:     target,
		ScanID:     db.ScanID,
		Timeout:    time.Duration(db.Timeout),
		RequestID:  db.RequestID,
		Timestamp:  db.Timestamp,
		Priority:   coremodels.RequestPriority(db.Priority),
		RetryCount: db.RetryCount,
	}

	// Convert config from JSON string
	if db.Config != nil {
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(*db.Config), &config); err != nil {
			return nil, err
		}
		core.Config = config
	}

	// Convert metadata from JSON string
	if db.Metadata != nil {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(*db.Metadata), &metadata); err != nil {
			return nil, err
		}
		core.Metadata = metadata
	}

	// Initialize empty maps if nil
	if core.Config == nil {
		core.Config = make(map[string]interface{})
	}
	if core.Metadata == nil {
		core.Metadata = make(map[string]string)
	}

	return core, nil
}

// ConvertFindingToDatabase converts core Finding to database model
func ConvertFindingToDatabase(core *coremodels.Finding, responseID string) (*FindingDB, error) {
	if core == nil {
		return nil, nil
	}

	db := &FindingDB{
		ID:          core.ID,
		Title:       core.Title,
		Description: core.Description,
		Severity:    string(core.Severity),
		Confidence:  string(core.Confidence),
		Category:    core.Category,
		Domain:      string(core.Domain),
		Timestamp:   core.Timestamp,
		PluginID:    core.PluginID,
		RequestID:   core.RequestID,
		Verified:    core.Verified,
	}

	// Parse responseID as UUID
	if responseID != "" {
		responseUUID, err := uuid.Parse(responseID)
		if err != nil {
			return nil, err
		}
		db.ResponseID = responseUUID
	}

	// Handle nullable string fields
	if core.Location != "" {
		db.Location = &core.Location
	}
	if core.Payload != "" {
		db.Payload = &core.Payload
	}
	if core.Response != "" {
		db.Response = &core.Response
	}
	if core.Remediation != "" {
		db.Remediation = &core.Remediation
	}

	// Convert evidence to JSON string
	if len(core.Evidence) > 0 {
		evidenceJSON, err := json.Marshal(core.Evidence)
		if err != nil {
			return nil, err
		}
		evidenceStr := string(evidenceJSON)
		db.Evidence = &evidenceStr
	}

	// Convert references to JSON string
	if len(core.References) > 0 {
		referencesJSON, err := json.Marshal(core.References)
		if err != nil {
			return nil, err
		}
		referencesStr := string(referencesJSON)
		db.References = &referencesStr
	}

	// Convert tags to JSON string
	if len(core.Tags) > 0 {
		tagsJSON, err := json.Marshal(core.Tags)
		if err != nil {
			return nil, err
		}
		tagsStr := string(tagsJSON)
		db.Tags = &tagsStr
	}

	// Convert metadata to JSON string
	if len(core.Metadata) > 0 {
		metadataJSON, err := json.Marshal(core.Metadata)
		if err != nil {
			return nil, err
		}
		metadataStr := string(metadataJSON)
		db.Metadata = &metadataStr
	}

	// Convert CVSS to JSON string
	if core.CVSS != nil {
		cvssJSON, err := json.Marshal(core.CVSS)
		if err != nil {
			return nil, err
		}
		cvssStr := string(cvssJSON)
		db.CVSS = &cvssStr
	}

	return db, nil
}

// ConvertFindingFromDatabase converts database Finding to core model
func ConvertFindingFromDatabase(db *FindingDB) (*coremodels.Finding, error) {
	if db == nil {
		return nil, nil
	}

	core := &coremodels.Finding{
		ID:          db.ID,
		Title:       db.Title,
		Description: db.Description,
		Severity:    coremodels.SeverityLevel(db.Severity),
		Confidence:  coremodels.ConfidenceLevel(db.Confidence),
		Category:    db.Category,
		Domain:      coremodels.SecurityDomain(db.Domain),
		Timestamp:   db.Timestamp,
		PluginID:    db.PluginID,
		RequestID:   db.RequestID,
		Verified:    db.Verified,
	}

	// Handle nullable fields
	if db.Location != nil {
		core.Location = *db.Location
	}
	if db.Payload != nil {
		core.Payload = *db.Payload
	}
	if db.Response != nil {
		core.Response = *db.Response
	}
	if db.Remediation != nil {
		core.Remediation = *db.Remediation
	}

	// Convert evidence from JSON string
	if db.Evidence != nil {
		var evidence map[string]interface{}
		if err := json.Unmarshal([]byte(*db.Evidence), &evidence); err != nil {
			return nil, err
		}
		core.Evidence = evidence
	}

	// Convert references from JSON string
	if db.References != nil {
		var references []string
		if err := json.Unmarshal([]byte(*db.References), &references); err != nil {
			return nil, err
		}
		core.References = references
	}

	// Convert tags from JSON string
	if db.Tags != nil {
		var tags []string
		if err := json.Unmarshal([]byte(*db.Tags), &tags); err != nil {
			return nil, err
		}
		core.Tags = tags
	}

	// Convert metadata from JSON string
	if db.Metadata != nil {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(*db.Metadata), &metadata); err != nil {
			return nil, err
		}
		core.Metadata = metadata
	}

	// Convert CVSS from JSON string
	if db.CVSS != nil {
		var cvss coremodels.CVSSScore
		if err := json.Unmarshal([]byte(*db.CVSS), &cvss); err != nil {
			return nil, err
		}
		core.CVSS = &cvss
	}

	// Initialize empty maps/slices if nil
	if core.Evidence == nil {
		core.Evidence = make(map[string]interface{})
	}
	if core.References == nil {
		core.References = []string{}
	}
	if core.Tags == nil {
		core.Tags = []string{}
	}
	if core.Metadata == nil {
		core.Metadata = make(map[string]string)
	}

	return core, nil
}
