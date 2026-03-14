import json

class JSONLogger:
    def __init__(self, filename='audit.jsonl'):
        self.filename = filename

    def log_event(self, event_type, metadata):
        timestamp = '2026-03-14 03:55:27'
        log_entry = {'timestamp': timestamp, 'event_type': event_type, 'metadata': metadata}
        with open(self.filename, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

# Example usage:
# logger = JSONLogger()
# logger.log_event('transition', {'identity': 'user1', 'action': 'moved to state X'})
# logger.log_event('identity_sync', {'identity': 'user1', 'synced_with': 'service_A'})
# logger.log_event('quantum_veto', {'vetoed_event': 'event1'})
