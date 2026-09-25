"""
Test to verify that flagged intelligence is blocked even if scam detection fails.
This tests the fix for the issue where flagged UPI IDs, bank accounts, and links 
were not being blocked if the current message wasn't detected as a scam.
"""

import logging
from controller import handle_message
from storage import add_flagged_intelligence, _flagged_upi_ids, _flagged_bank_accounts, _flagged_phishing_links

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_flagged_upi_is_blocked():
    """Test that a previously flagged UPI ID blocks the conversation even if not detected as scam."""
    
    # Clear previous flags
    _flagged_upi_ids.clear()
    _flagged_bank_accounts.clear()
    _flagged_phishing_links.clear()
    
    # First conversation: Add a suspicious UPI to flagged list
    flagged_upi = "scammer@paytm"
    add_flagged_intelligence(upi_ids=[flagged_upi])
    
    logger.info(f"✅ Added flagged UPI: {flagged_upi}")
    logger.info(f"📊 Flagged UPIs count: {len(_flagged_upi_ids)}")
    
    # Second conversation: Send the same UPI in a message with minimal scam indicators
    # This should be blocked due to flagged intelligence, EVEN if not detected as scam
    response = handle_message(
        conversation_id="test_conv_123",
        message=f"Hello, please send money to {flagged_upi}",  # One keyword only: "send"
        ip="192.168.1.1"
    )
    
    logger.info(f"📬 Response blocked: {response.blocked}")
    logger.info(f"🎯 Flagged match: {response.flagged_match}")
    logger.info(f"💬 Reply: {response.honeypot_reply}")
    
    # Assert that it was blocked
    assert response.blocked == True, f"Expected blocked=True, got {response.blocked}"
    assert response.flagged_match == True, f"Expected flagged_match=True, got {response.flagged_match}"
    logger.info("✅ TEST PASSED: Flagged UPI blocked conversation even without scam detection!")


def test_flagged_link_is_blocked():
    """Test that a previously flagged phishing link blocks the conversation."""
    
    # Clear previous flags
    _flagged_upi_ids.clear()
    _flagged_bank_accounts.clear()
    _flagged_phishing_links.clear()
    
    # Add a flagged link
    flagged_link = "malicious.site.com"
    add_flagged_intelligence(phishing_links=[flagged_link])
    
    logger.info(f"✅ Added flagged link: {flagged_link}")
    
    # Send a message with the flagged link but minimal scam indicators
    response = handle_message(
        conversation_id="test_conv_456",
        message=f"Visit {flagged_link} please",  # Very minimal scam indicators
        ip="192.168.1.1"
    )
    
    logger.info(f"📬 Response blocked: {response.blocked}")
    logger.info(f"🎯 Flagged match: {response.flagged_match}")
    
    # Assert that it was blocked
    assert response.blocked == True, f"Expected blocked=True, got {response.blocked}"
    assert response.flagged_match == True, f"Expected flagged_match=True, got {response.flagged_match}"
    logger.info("✅ TEST PASSED: Flagged link blocked conversation!")


def test_flagged_bank_account_is_blocked():
    """Test that a previously flagged bank account blocks the conversation."""
    
    # Clear previous flags
    _flagged_upi_ids.clear()
    _flagged_bank_accounts.clear()
    _flagged_phishing_links.clear()
    
    # Add a flagged account
    flagged_account = "123456789012"
    add_flagged_intelligence(bank_accounts=[flagged_account])
    
    logger.info(f"✅ Added flagged account: {flagged_account}")
    
    # Send a message with the flagged account
    response = handle_message(
        conversation_id="test_conv_789",
        message=f"Please transfer to account {flagged_account}",
        ip="192.168.1.1"
    )
    
    logger.info(f"📬 Response blocked: {response.blocked}")
    logger.info(f"🎯 Flagged match: {response.flagged_match}")
    
    # Assert that it was blocked
    assert response.blocked == True, f"Expected blocked=True, got {response.blocked}"
    assert response.flagged_match == True, f"Expected flagged_match=True, got {response.flagged_match}"
    logger.info("✅ TEST PASSED: Flagged bank account blocked conversation!")


if __name__ == "__main__":
    test_flagged_upi_is_blocked()
    test_flagged_link_is_blocked()
    test_flagged_bank_account_is_blocked()
    logger.info("\n✅✅✅ All tests passed! Flagged intelligence blocking is working correctly!")
