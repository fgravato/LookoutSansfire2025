# Standard library imports
import datetime
import time
import json
import requests
import logging
from typing import Optional

# Lookout MRA client imports
from lookout_mra_client.lookout_logger import init_lookout_logger
from lookout_mra_client.event_forwarders.event_forwarder import EventForwarder
from lookout_mra_client.mra_v2_stream_thread import MRAv2StreamThread

class RequestBinForwarder(EventForwarder):
    """
    A forwarder that sends Lookout MRA events to a RequestBin endpoint.
    
    This class extends the EventForwarder interface to forward security events
    from Lookout Mobile Risk Assessment (MRA) to a RequestBin for inspection
    and debugging purposes.
    """
    def __init__(self, request_bin_url: str, timeout: int = 30):
        """
        Initialize the RequestBin forwarder.
        
        Args:
            request_bin_url: The URL of the RequestBin endpoint
            timeout: Request timeout in seconds (default: 30)
        """
        self.request_bin_url = request_bin_url
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
    def write(self, event: dict, entName: str = ""):
        """
        Forward an event to the RequestBin with comprehensive error handling.
        
        This method implements the EventForwarder interface's write method.
        It formats the event with additional metadata and sends it to the
        configured RequestBin URL.
        
        Args:
            event: The event data dictionary to forward
            entName: The entity name associated with the event (optional)
        """
        try:
            # Prepare the payload with timestamp and entity information
            payload = {
                "timestamp": datetime.datetime.now().isoformat(),
                "entity_name": entName,
                "event": event
            }
            
            # Send POST request to RequestBin with appropriate headers
            response = requests.post(
                self.request_bin_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Lookout-RequestBin-Forwarder/1.0"
                },
                timeout=self.timeout
            )
            
            # Log the response status for monitoring
            if response.status_code == 200:
                self.logger.info(f"Successfully forwarded event to request bin. Status: {response.status_code}")
            else:
                self.logger.warning(f"Request bin returned non-200 status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            # Handle network-related errors (timeouts, connection issues, etc.)
            self.logger.error(f"Failed to forward event to request bin: {e}")
            # Also print to stdout as fallback for visibility
            print(f"FAILED TO FORWARD - Event: {json.dumps(event)}")
        except Exception as e:
            # Catch any other unexpected errors
            self.logger.error(f"Unexpected error forwarding event: {e}")
            print(f"UNEXPECTED ERROR - Event: {json.dumps(event)}")

def main():
    """
    Main function to set up and run the Lookout MRA to RequestBin forwarding.
    
    This function:
    1. Initializes logging
    2. Configures the RequestBin forwarder
    3. Sets up the MRA stream with appropriate parameters
    4. Starts the stream thread and handles graceful shutdown
    """
    # Initialize logging to file
    init_lookout_logger("./mra_v2_demo_script.log")
    
    # RequestBin endpoint URL where events will be forwarded
    request_bin_url = "http://149.28.54.231/bin/4lr20ay1"
    
    # Create an instance of our custom forwarder
    forwarder = RequestBinForwarder(request_bin_url)
    
    # Set start time to retrieve events from the past 24 hours
    start_time = datetime.datetime.now() - datetime.timedelta(days=1)
    # Ensure timezone is set to UTC for API compatibility
    start_time = start_time.replace(tzinfo=datetime.timezone.utc)
    
    # Define which event types to retrieve from the MRA API
    # THREAT: Security threat events
    # DEVICE: Device status and information events
    # AUDIT: User and system audit events
    event_type = ["THREAT", "DEVICE", "AUDIT"]
    
    # Configure the MRA stream arguments
    stream_args = {
        "api_domain": "https://api.lookout.com",  # Lookout API endpoint
        "api_key": "eyJraWQiOiIxODoxNjo3NzoyMjo2Mzo0YjpmZjoyMzoxOTpmMTpjZjozYTpjYjphZTozODo0NDo5NjpmYTozNDpjMDpjMTo5Zjo2Njo0ZDowZjo2Zjo2ODpjNzpmZDowNDpkOTo0MiIsImN0eSI6IkpXUyIsImVuYyI6IkExMjhHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.eSLgQChU0DkYMBPdP8ICxQc5O1c6TSxfUEZ6nT_CqBVADpev1VAohSMDJoXC3CeTw1mgjwfqjDL_ozKt13G9Ql4U5IA8l3Kl3UXV8AGy0eINN-sFO60H0b-H9lmzj1ue8Sc_dkS02Mv3zKpBcXXyTW6W_XdzEv38rH0r8_4fLo53zxqI44CjUVpiRysHEG0BBJNkRU0QrUf4xkOkVxR-GdQVxaT0_4R5PQxLsRiN7Yb5V6_csVHawCBIlY6tDGl_SsExOqD0M8o4IzEV_OpnU9RB2lK7rnPGN_jo5dEX4RhtbddyCcUoCFDda9vXgDr-2ziFpjiIZW7MOmSB-RGpdAKCcyI7NfpRG0DUTh_rHBRE2a-8sFFiVXImxJv3wZyLCO4Ba9IEMLx9n4KUjKhBczEwCxHyPk8Dlz-I81MzEiZcvYVFEOixtrnuKOlZERT33hjmknRKKlgtUROXXiS195PGuQAhx8ICfKb1ZRRS4m7K_2Q0R6lrSKnkHkt9SNHZ2CYuEwWHzksc0-ZPFZMM60p4Vkcfd7V2ipZ3s-pAo8r_UQ4DAegUH_124IZGR4xu5SCAvpm1G4xlWZB8j4srx-UzVJkufgsIPd3gOd-B-bq36jIk_OHXUyLfbkfwcBA6d7APUA09RpEEQCWc1OJb7aX_8KB2ousbH59UNqu7Nzg.GhbiwTWPNClEF5Jv.GVIebbcCjewHEwvJSaXIiGapIFnMdZYxIl14qBCKjp2tslxFtnv30cilfVd8NibCpZuMkLohfv3LfAJnSNMD-Kkr9s4BQzasOD4kz-KQA72YGeAHonWjwLvYy_CCL6SaTmhvUB-o3_J4Y1EQVax04z4BfByv2XNloF6Jx07tVD3JwSYbyQU0eDIOHtzjpzLqXmPTPXoNooMHhuaaT5VhYlTo2bIkSkCpjd0GEOk8m-9j5bDxaawUUtnvWu-qwoGNBvwYmRF5rCl0ouO8Mh-RI2Upq-GHfYgS6sphJBSDMCJ_zo1AWx7Qpa8x5eq7k_z1HVdQWuW53cHq-EIXHbRZ6xEsSM4pE3Su66_LGQlPQU0YMbPotK_81iEO3PCr-sOhvaqFjJjLFStpZ6s833vzmf6wEqwR2GM79LkK8W8O0I54ysaZwxVzcRqAO3INMrOw0Ejm9eUXugqUVgedVH4dY_8qlImjR-dlAgfQqeCs0h0ybZYk1U5ECc7EFm3UPUdKeoRMmhyXhMot9OtDSYs8oWTCgOjKS-KTdpMMxZIx6hT5me5F0p4urzqcMANDq0DD_Pi5QkRyWEN36_HzHlpv8mKsGLd1EmnmSmHlNagz_emPXlpt3e9DD5XvjjItiBpddwmLUzWuULF5SIFSXCyY9MJ5pHGKszPO-Sx5JYplgh9r5puchJzQxq7ezYMfvwsVnJWuJfvLuPntCHVPkBMz86UBx68L7g_8NAU7OnLsCCZPuHUwzklyu10rGP-6BnG83gq-ECF7QTYxtGD-pgQ9_sR9Cavwn1WyuwF2ROc6M3dqpQIg4JVCUimQmIF2zIKZa6mUN4_5P2CpriFUmftSthtzWNRXCwlBx3k0HghSKwiuQHZrPVSFWFiCHMyhau7AbToIN_eKGTUkRYy4quQszvr_WQbv0HR8y0_BzGMEPRIg3NadEzthNLMtsvttLrXLqLRhUqscZ_b9ilO9nUOss_13zI4lgSVtL0aqBtQo2y65UQTd_aWBVh4pdZHKbd8nWBR4-E_GWB54A2EEi9dA52WEjgWWX5krkklO61Ynr4qQTS8bSktj_D7oocXA38DawnBhhiT_Zfc52cCTkzI6HOy3BFnlgdFNXi5pm0TjaCJZ5FvUq42gGZMi87asBeX22HRUJwc8fcpJCuneDlLYkP4QXII3Msm9w92PWwIyW3vs_LkAijlqG7lfCL3G_HYhAcvXSk2Z8d4bE72RNwsw98ikUJEhuG-4nOLF5VpQePhzhRdgdtVul6SGcfdwg3URZMuIiE2Dwq_VlutETnKswX7Zv4g3BXDckWNYMnexrB-AmbgnZjvq8o_WW2r0Nxwwty6gLbmQiOKlMEczrSlq_zxJH1kxH2cAE19EvEXCb-vK4lv9HLjgWslySrGYODtfqpsZsZXFfuSmeq2BQUjj4-Z-1p_v9A1bnI8dbm8WVOqYyl_7vwM8sMDPvmZjuk7Iq3IgZTLAQd3AzeaWYTzqhBiy9_SiOQ52p3WrIeIPdv102r8VmrmMSLs7l7zQy2Z8cdZZE3i2_QBdZqFZuvt27LvS-MzFDmzxmv7eNu4LtRcWMsVJcBXe0t4WZYQIchdQGNkGecX_QWynFE_lpYujDzAO7546xkMDkpfD0RUHsKI8sGfrUmejKdhN64Wup_J44TpfqQ6d98-7sg.vPB4rfsiYV4RdDxsy1ckgA",  # Replace with your actual API key
        "start_time": start_time,  # Start time for event retrieval
        "event_type": ",".join(event_type),  # Convert event types to comma-separated string
    }
    
    # Create the MRA stream thread with our forwarder
    # "demoEnt" is the entity name that will be included with forwarded events
    mra = MRAv2StreamThread("demoEnt", forwarder, **stream_args)
    
    # Display startup information
    print(f"Starting Lookout MRA stream forwarding to: {request_bin_url}")
    print("Press Ctrl-C to stop...")
    
    # Start the stream thread and implement graceful shutdown with Ctrl-C
    try:
        # Start the MRA stream thread
        mra.start()
        # Keep the main thread alive with a sleep loop
        # This allows the background thread to continue running
        while True:
            time.sleep(100)
    except KeyboardInterrupt:
        # Handle Ctrl-C by shutting down gracefully
        print("\nShutting down gracefully...")
        # Signal the thread to stop
        mra.shutdown_flag.set()
        # Wait for the thread to finish
        mra.join()
        print("Shutdown complete.")

if __name__ == "__main__":
    # Entry point when script is run directly
    # This allows the script to be imported without running main()
    main()
