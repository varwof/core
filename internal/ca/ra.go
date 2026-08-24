package ca

import (
	"fmt"

	"github.com/varwof/engine/db"
)

type SignCSRCallback func(csrDER []byte, cn, profile, caName string) (serial string, certDER []byte, err error)

func SubmitRequest(database *db.DB, csrDER []byte, cn, sanList, profile, caName, requester string, requiredApprovals int) (int, error) {
	id, err := database.CreateRARequest(csrDER, cn, sanList, profile, caName, requester, requiredApprovals)
	if err != nil {
		return 0, fmt.Errorf("submit ra request: %w", err)
	}
	return id, nil
}

func ProcessApproval(database *db.DB, requestID int, approver, decision, comment string, signFn SignCSRCallback) (approved bool, issuedSerial string, err error) {
	req, err := database.GetRARequest(requestID)
	if err != nil {
		return false, "", fmt.Errorf("get request: %w", err)
	}
	if req.Status != "pending" {
		return false, "", fmt.Errorf("request %d is not pending (status: %s)", requestID, req.Status)
	}

	approvedCount, totalRequired, err := database.AddRAApproval(requestID, approver, decision, comment)
	if err != nil {
		return false, "", fmt.Errorf("add approval: %w", err)
	}

	if decision != "approved" {
		return false, "", nil
	}

	if approvedCount < totalRequired {
		return false, "", nil
	}

	serial, _, err := signFn(req.CSRDER, req.CommonName, req.Profile, req.CAName)
	if err != nil {
		database.UpdateRARequestStatus(requestID, "failed", "", "")
		return false, "", fmt.Errorf("sign failed: %w", err)
	}

	if err := database.UpdateRARequestStatus(requestID, "issued", serial, ""); err != nil {
		return false, "", fmt.Errorf("update status: %w", err)
	}

	return true, serial, nil
}

func RejectRequest(database *db.DB, requestID int, reason string) error {
	req, err := database.GetRARequest(requestID)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}
	if req.Status != "pending" {
		return fmt.Errorf("request %d is not pending (status: %s)", requestID, req.Status)
	}
	if err := database.UpdateRARequestStatus(requestID, "rejected", "", reason); err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}
