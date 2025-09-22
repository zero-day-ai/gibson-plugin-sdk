package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coremodels "github.com/zero-day-ai/gibson-sdk/pkg/core/models"
)

func TestConvertPluginInfo(t *testing.T) {
	// Create core model
	core := &coremodels.PluginInfo{
		ID:           uuid.New(),
		Name:         "test-plugin",
		Version:      "1.0.0",
		Description:  "Test plugin description",
		Author:       "Test Author",
		Domains:      []coremodels.SecurityDomain{coremodels.DomainInterface, coremodels.DomainModel},
		Capabilities: []string{"scan", "validate"},
		Config:       map[string]interface{}{"timeout": 30, "retries": 3},
		SDKVersion:   "1.0.0",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Convert to database model
	db, err := ConvertPluginInfoToDatabase(core)
	require.NoError(t, err)
	require.NotNil(t, db)

	assert.Equal(t, core.ID, db.ID)
	assert.Equal(t, core.Name, db.Name)
	assert.Equal(t, core.Version, db.Version)
	assert.Equal(t, core.Author, db.Author)
	assert.Equal(t, core.SDKVersion, db.SDKVersion)
	assert.NotNil(t, db.Description)
	assert.Equal(t, core.Description, *db.Description)
	assert.NotNil(t, db.Domains)
	assert.NotNil(t, db.Capabilities)
	assert.NotNil(t, db.Config)

	// Convert back to core model
	convertedCore, err := ConvertPluginInfoFromDatabase(db)
	require.NoError(t, err)
	require.NotNil(t, convertedCore)

	assert.Equal(t, core.ID, convertedCore.ID)
	assert.Equal(t, core.Name, convertedCore.Name)
	assert.Equal(t, core.Version, convertedCore.Version)
	assert.Equal(t, core.Description, convertedCore.Description)
	assert.Equal(t, core.Author, convertedCore.Author)
	assert.Equal(t, core.SDKVersion, convertedCore.SDKVersion)
	assert.Equal(t, len(core.Domains), len(convertedCore.Domains))
	assert.Equal(t, len(core.Capabilities), len(convertedCore.Capabilities))
	assert.Equal(t, len(core.Config), len(convertedCore.Config))
}

func TestConvertTarget(t *testing.T) {
	// Create core model
	core := &coremodels.Target{
		ID:          uuid.New(),
		Name:        "test-target",
		Type:        coremodels.TargetTypeAPI,
		URL:         "https://api.example.com",
		Credentials: map[string]string{"api_key": "secret"},
		Config:      map[string]string{"timeout": "30s"},
		Tags:        []string{"production", "critical"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Convert to database model
	db, err := ConvertTargetToDatabase(core)
	require.NoError(t, err)
	require.NotNil(t, db)

	assert.Equal(t, core.ID, db.ID)
	assert.Equal(t, core.Name, db.Name)
	assert.Equal(t, string(core.Type), db.Type)
	assert.NotNil(t, db.URL)
	assert.Equal(t, core.URL, *db.URL)
	assert.NotNil(t, db.Credentials)
	assert.NotNil(t, db.Config)
	assert.NotNil(t, db.Tags)

	// Convert back to core model
	convertedCore, err := ConvertTargetFromDatabase(db)
	require.NoError(t, err)
	require.NotNil(t, convertedCore)

	assert.Equal(t, core.ID, convertedCore.ID)
	assert.Equal(t, core.Name, convertedCore.Name)
	assert.Equal(t, core.Type, convertedCore.Type)
	assert.Equal(t, core.URL, convertedCore.URL)
	assert.Equal(t, len(core.Credentials), len(convertedCore.Credentials))
	assert.Equal(t, len(core.Config), len(convertedCore.Config))
	assert.Equal(t, len(core.Tags), len(convertedCore.Tags))
}

func TestConvertFinding(t *testing.T) {
	// Create core model
	core := &coremodels.Finding{
		ID:          uuid.New(),
		Title:       "SQL Injection Vulnerability",
		Description: "SQL injection found in login endpoint",
		Severity:    coremodels.SeverityHigh,
		Confidence:  coremodels.ConfidenceHigh,
		Category:    "injection",
		Domain:      coremodels.DomainInterface,
		Evidence:    map[string]interface{}{"payload": "' OR 1=1 --", "response_time": 150},
		Location:    "/api/login",
		Payload:     "username=' OR 1=1 --&password=test",
		Response:    "HTTP/1.1 200 OK",
		Remediation: "Use parameterized queries",
		References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		Timestamp:   time.Now(),
		PluginID:    "sql-injection-plugin",
		Tags:        []string{"injection", "critical"},
		Metadata:    map[string]string{"scan_id": "123", "endpoint": "/api/login"},
		RequestID:   "req-123",
		Verified:    true,
		CVSS: &coremodels.CVSSScore{
			Version: "3.1",
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Score:   9.8,
			Rating:  "Critical",
		},
	}

	responseID := uuid.New().String()

	// Convert to database model
	db, err := ConvertFindingToDatabase(core, responseID)
	require.NoError(t, err)
	require.NotNil(t, db)

	assert.Equal(t, core.ID, db.ID)
	assert.Equal(t, core.Title, db.Title)
	assert.Equal(t, core.Description, db.Description)
	assert.Equal(t, string(core.Severity), db.Severity)
	assert.Equal(t, string(core.Confidence), db.Confidence)
	assert.Equal(t, core.Category, db.Category)
	assert.Equal(t, string(core.Domain), db.Domain)
	assert.Equal(t, core.PluginID, db.PluginID)
	assert.Equal(t, core.RequestID, db.RequestID)
	assert.Equal(t, core.Verified, db.Verified)
	assert.NotNil(t, db.Evidence)
	assert.NotNil(t, db.Location)
	assert.NotNil(t, db.Payload)
	assert.NotNil(t, db.Response)
	assert.NotNil(t, db.Remediation)
	assert.NotNil(t, db.References)
	assert.NotNil(t, db.Tags)
	assert.NotNil(t, db.Metadata)
	assert.NotNil(t, db.CVSS)

	// Convert back to core model
	convertedCore, err := ConvertFindingFromDatabase(db)
	require.NoError(t, err)
	require.NotNil(t, convertedCore)

	assert.Equal(t, core.ID, convertedCore.ID)
	assert.Equal(t, core.Title, convertedCore.Title)
	assert.Equal(t, core.Description, convertedCore.Description)
	assert.Equal(t, core.Severity, convertedCore.Severity)
	assert.Equal(t, core.Confidence, convertedCore.Confidence)
	assert.Equal(t, core.Category, convertedCore.Category)
	assert.Equal(t, core.Domain, convertedCore.Domain)
	assert.Equal(t, core.PluginID, convertedCore.PluginID)
	assert.Equal(t, core.RequestID, convertedCore.RequestID)
	assert.Equal(t, core.Verified, convertedCore.Verified)
	assert.Equal(t, core.Location, convertedCore.Location)
	assert.Equal(t, core.Payload, convertedCore.Payload)
	assert.Equal(t, core.Response, convertedCore.Response)
	assert.Equal(t, core.Remediation, convertedCore.Remediation)
	assert.Equal(t, len(core.Evidence), len(convertedCore.Evidence))
	assert.Equal(t, len(core.References), len(convertedCore.References))
	assert.Equal(t, len(core.Tags), len(convertedCore.Tags))
	assert.Equal(t, len(core.Metadata), len(convertedCore.Metadata))
	assert.NotNil(t, convertedCore.CVSS)
	assert.Equal(t, core.CVSS.Score, convertedCore.CVSS.Score)
}

func TestConvertAssessRequest(t *testing.T) {
	target := &coremodels.Target{
		ID:   uuid.New(),
		Name: "test-target",
		Type: coremodels.TargetTypeAPI,
	}

	// Create core model
	core := &coremodels.AssessRequest{
		ID:         uuid.New(),
		Target:     target,
		Config:     map[string]interface{}{"depth": 5, "enabled": true},
		ScanID:     "scan-123",
		Timeout:    5 * time.Minute,
		Metadata:   map[string]string{"user": "admin", "environment": "prod"},
		RequestID:  "req-456",
		Timestamp:  time.Now(),
		Priority:   coremodels.PriorityHigh,
		RetryCount: 2,
	}

	// Convert to database model
	db, err := ConvertAssessRequestToDatabase(core)
	require.NoError(t, err)
	require.NotNil(t, db)

	assert.Equal(t, core.ID, db.ID)
	assert.Equal(t, core.Target.ID, db.TargetID)
	assert.Equal(t, core.ScanID, db.ScanID)
	assert.Equal(t, int64(core.Timeout), db.Timeout)
	assert.Equal(t, core.RequestID, db.RequestID)
	assert.Equal(t, string(core.Priority), db.Priority)
	assert.Equal(t, core.RetryCount, db.RetryCount)
	assert.NotNil(t, db.Config)
	assert.NotNil(t, db.Metadata)

	// Convert back to core model
	convertedCore, err := ConvertAssessRequestFromDatabase(db, target)
	require.NoError(t, err)
	require.NotNil(t, convertedCore)

	assert.Equal(t, core.ID, convertedCore.ID)
	assert.Equal(t, core.Target.ID, convertedCore.Target.ID)
	assert.Equal(t, core.ScanID, convertedCore.ScanID)
	assert.Equal(t, core.Timeout, convertedCore.Timeout)
	assert.Equal(t, core.RequestID, convertedCore.RequestID)
	assert.Equal(t, core.Priority, convertedCore.Priority)
	assert.Equal(t, core.RetryCount, convertedCore.RetryCount)
	assert.Equal(t, len(core.Config), len(convertedCore.Config))
	assert.Equal(t, len(core.Metadata), len(convertedCore.Metadata))
}

func TestConvertNilModels(t *testing.T) {
	// Test nil conversions
	pluginDB, err := ConvertPluginInfoToDatabase(nil)
	assert.NoError(t, err)
	assert.Nil(t, pluginDB)

	pluginCore, err := ConvertPluginInfoFromDatabase(nil)
	assert.NoError(t, err)
	assert.Nil(t, pluginCore)

	targetDB, err := ConvertTargetToDatabase(nil)
	assert.NoError(t, err)
	assert.Nil(t, targetDB)

	targetCore, err := ConvertTargetFromDatabase(nil)
	assert.NoError(t, err)
	assert.Nil(t, targetCore)
}

func TestStringArrayHelpers(t *testing.T) {
	// Test StringArray
	var sa StringArray

	// Test scanning from string
	err := sa.Scan(`["item1", "item2", "item3"]`)
	require.NoError(t, err)
	assert.Len(t, sa, 3)
	assert.Equal(t, "item1", sa[0])

	// Test value conversion
	value, err := sa.Value()
	require.NoError(t, err)
	assert.Contains(t, value.(string), "item1")

	// Test nil scan
	var nilSA StringArray
	err = nilSA.Scan(nil)
	require.NoError(t, err)
	assert.Nil(t, nilSA)
}

func TestStringMapHelpers(t *testing.T) {
	// Test StringMap
	var sm StringMap

	// Test scanning from string
	err := sm.Scan(`{"key1": "value1", "key2": "value2"}`)
	require.NoError(t, err)
	assert.Len(t, sm, 2)
	assert.Equal(t, "value1", sm["key1"])

	// Test value conversion
	value, err := sm.Value()
	require.NoError(t, err)
	assert.Contains(t, value.(string), "key1")

	// Test nil scan
	var nilSM StringMap
	err = nilSM.Scan(nil)
	require.NoError(t, err)
	assert.Nil(t, nilSM)
}
