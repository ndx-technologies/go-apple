package appstoreconnect

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
)

type ResourceType string

const (
	ResourceAnalyticsReportRequests ResourceType = "analyticsReportRequests"
	ResourceAnalyticsReports        ResourceType = "analyticsReports"
	ResourceApps                    ResourceType = "apps"
)

type AccessType string

const (
	Ongoing         AccessType = "ONGOING"
	OneTimeSnapshot AccessType = "ONE_TIME_SNAPSHOT"
)

type ReportCategory string

const (
	CategoryAppUsage           ReportCategory = "APP_USAGE"
	CategoryAppStoreEngagement ReportCategory = "APP_STORE_ENGAGEMENT"
	CategoryCommerce           ReportCategory = "COMMERCE"
	CategoryFrameworkUsage     ReportCategory = "FRAMEWORK_USAGE"
	CategoryPerformance        ReportCategory = "PERFORMANCE"
)

// AnalyticsReportRequestCreateRequest
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportrequestcreaterequest
type AnalyticsReportRequestCreateRequest struct {
	Data AnalyticsReportRequestCreateData `json:"data"`
}

type AnalyticsReportRequestCreateData struct {
	Type          ResourceType                                  `json:"type"`
	Attributes    AnalyticsReportRequestCreateDataAttributes    `json:"attributes"`
	Relationships AnalyticsReportRequestCreateDataRelationships `json:"relationships"`
}

type AnalyticsReportRequestCreateDataAttributes struct {
	AccessType AccessType `json:"accessType"`
}

type AnalyticsReportRequestCreateDataRelationships struct {
	App AnalyticsReportRequestCreateDataApp `json:"app"`
}

type AnalyticsReportRequestCreateDataApp struct {
	Data AnalyticsReportRequestCreateDataAppData `json:"data"`
}

type AnalyticsReportRequestCreateDataAppData struct {
	Type ResourceType `json:"type"`
	ID   string       `json:"id"`
}

// AnalyticsReportRequestResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportrequestresponse
type AnalyticsReportRequestResponse struct {
	Data  AnalyticsReportRequest `json:"data"`
	Links ResourceLinks          `json:"links"`
}

// AnalyticsReportRequest
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportrequest
type AnalyticsReportRequest struct {
	Type          ResourceType                        `json:"type"`
	ID            string                              `json:"id"`
	Attributes    AnalyticsReportRequestAttributes    `json:"attributes,omitempty"`
	Relationships AnalyticsReportRequestRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks                       `json:"links,omitempty"`
}

type AnalyticsReportRequestAttributes struct {
	AccessType             AccessType `json:"accessType"`
	StoppedDueToInactivity bool       `json:"stoppedDueToInactivity,omitempty"`
}

type AnalyticsReportRequestRelationships struct {
	Reports AnalyticsReportRequestReportsRelationship `json:"reports,omitempty"`
}

type AnalyticsReportRequestReportsRelationship struct {
	Links ResourceLinks                              `json:"links,omitempty"`
	Data  []AnalyticsReportRequestReportsLinkageData `json:"data,omitempty"`
}

type AnalyticsReportRequestReportsLinkageData struct {
	Type ResourceType `json:"type"`
	ID   string       `json:"id"`
}

// AnalyticsReportsResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportsresponse
type AnalyticsReportsResponse struct {
	Data  []AnalyticsReport `json:"data"`
	Links ResourceLinks     `json:"links"`
}

// AnalyticsReport
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreport
type AnalyticsReport struct {
	Type       ResourceType              `json:"type"`
	ID         string                    `json:"id"`
	Attributes AnalyticsReportAttributes `json:"attributes,omitempty"`
	Links      ResourceLinks             `json:"links,omitempty"`
}

type AnalyticsReportAttributes struct {
	Name     string         `json:"name"`
	Category ReportCategory `json:"category"`
}

// AnalyticsReportRequestReportsLinkagesResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportrequestreportslinkagesresponse
type AnalyticsReportRequestReportsLinkagesResponse struct {
	Data  []AnalyticsReportRequestReportsLinkageData `json:"data"`
	Links ResourceLinks                              `json:"links"`
}

// AnalyticsReportRequestsResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportrequestsresponse
type AnalyticsReportRequestsResponse struct {
	Data  []AnalyticsReportRequest `json:"data"`
	Links ResourceLinks            `json:"links"`
}

// ResourceLinks
// https://developer.apple.com/documentation/appstoreconnectapi/resourcelinks
type ResourceLinks struct {
	Self string `json:"self,omitempty"`
}

const (
	// audience for App Store Connect API JWT tokens.
	audAppStoreConnect = "appstoreconnect-v1"
)

// RequestReports
// https://developer.apple.com/documentation/appstoreconnectapi/post-v1-analyticsreportrequests
func (s AppStoreConnectClient) RequestReports(ctx context.Context, body AnalyticsReportRequestCreateRequest) (*AnalyticsReportRequestResponse, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/v1/analyticsReportRequests", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportRequestResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetReports
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-analyticsreportrequests-_id_-reports
func (s AppStoreConnectClient) GetReports(ctx context.Context, requestID string, filterCategory ReportCategory, filterName string) (*AnalyticsReportsResponse, error) {
	url := s.BaseURL + "/v1/analyticsReportRequests/" + requestID + "/reports"

	var q []string
	if filterCategory != "" {
		q = append(q, "filter[category]="+string(filterCategory))
	}
	if filterName != "" {
		q = append(q, "filter[name]="+filterName)
	}
	if len(q) > 0 {
		url += "?" + strings.Join(q, "&")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportsResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetReportIDs
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-analyticsreportrequests-_id_-relationships-reports
func (s AppStoreConnectClient) GetReportIDs(ctx context.Context, requestID string) (*AnalyticsReportRequestReportsLinkagesResponse, error) {
	url := s.BaseURL + "/v1/analyticsReportRequests/" + requestID + "/relationships/reports"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportRequestReportsLinkagesResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AnalyticsReportDetailResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportresponse
type AnalyticsReportDetailResponse struct {
	Data  AnalyticsReportDetail `json:"data"`
	Links ResourceLinks         `json:"links"`
}

// AnalyticsReportDetail is a single report with relationships.
type AnalyticsReportDetail struct {
	Type          ResourceType                       `json:"type"`
	ID            string                             `json:"id"`
	Attributes    AnalyticsReportAttributes          `json:"attributes,omitzero"`
	Relationships AnalyticsReportDetailRelationships `json:"relationships,omitzero"`
	Links         ResourceLinks                      `json:"links,omitzero"`
}

type AnalyticsReportDetailRelationships struct {
	Instances AnalyticsReportInstancesRelationship `json:"instances,omitempty"`
}

type AnalyticsReportInstancesRelationship struct {
	Links ResourceLinks `json:"links,omitempty"`
}

// AnalyticsReportInstancesResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportinstancesresponse
type AnalyticsReportInstancesResponse struct {
	Data  []AnalyticsReportInstance `json:"data"`
	Links ResourceLinks             `json:"links"`
}

// AnalyticsReportInstance
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportinstance
type AnalyticsReportInstance struct {
	Type          string                               `json:"type"`
	ID            string                               `json:"id"`
	Attributes    AnalyticsReportInstanceAttributes    `json:"attributes,omitzero"`
	Relationships AnalyticsReportInstanceRelationships `json:"relationships,omitzero"`
}

type AnalyticsReportInstanceAttributes struct {
	Granularity    string `json:"granularity,omitempty"`
	ProcessingDate string `json:"processingDate,omitempty"`
}

type AnalyticsReportInstanceRelationships struct {
	Segments AnalyticsReportSegmentsRelationship `json:"segments,omitempty"`
}

type AnalyticsReportSegmentsRelationship struct {
	Links ResourceLinks `json:"links,omitempty"`
}

// AnalyticsReportSegmentsResponse
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportsegmentsresponse
type AnalyticsReportSegmentsResponse struct {
	Data  []AnalyticsReportSegment `json:"data"`
	Links ResourceLinks            `json:"links"`
}

// AnalyticsReportSegment
// https://developer.apple.com/documentation/appstoreconnectapi/analyticsreportsegment
type AnalyticsReportSegment struct {
	Type       string                           `json:"type"`
	ID         string                           `json:"id"`
	Attributes AnalyticsReportSegmentAttributes `json:"attributes,omitempty"`
}

type AnalyticsReportSegmentAttributes struct {
	Checksum string `json:"checksum,omitempty"`
	Size     int64  `json:"size,omitempty"`
	URL      string `json:"url,omitempty"`
}

// GetReportDetail fetches a single analytics report with relationships.
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-analyticsreports-_id_
func (s AppStoreConnectClient) GetReportDetail(ctx context.Context, reportID string) (*AnalyticsReportDetailResponse, error) {
	url := s.BaseURL + "/v1/analyticsReports/" + reportID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportDetailResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetReportInstances fetches instances for a specific report.
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-analyticsreports-_id_-instances
func (s AppStoreConnectClient) GetReportInstances(ctx context.Context, reportID string) (*AnalyticsReportInstancesResponse, error) {
	url := s.BaseURL + "/v1/analyticsReports/" + reportID + "/instances"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportInstancesResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetInstanceSegments fetches segments for a specific report instance.
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-analyticsreportinstances-_id_-segments
func (s AppStoreConnectClient) GetInstanceSegments(ctx context.Context, instanceID string) (*AnalyticsReportSegmentsResponse, error) {
	url := s.BaseURL + "/v1/analyticsReportInstances/" + instanceID + "/segments"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportSegmentsResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetReportRequests lists analytics report requests for an app.
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-apps-_id_-analyticsreportrequests
func (s AppStoreConnectClient) GetReportRequests(ctx context.Context, appID string) (*AnalyticsReportRequestsResponse, error) {
	url := s.BaseURL + "/v1/apps/" + appID + "/analyticsReportRequests"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTIssuer.GetJWT(audAppStoreConnect)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hresp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
		b, _ := io.ReadAll(hresp.Body)
		return nil, &ErrHTTP{Status: hresp.StatusCode, ResponseBody: string(b)}
	}

	var resp AnalyticsReportRequestsResponse
	if err := json.UnmarshalRead(hresp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
