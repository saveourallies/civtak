import pika
import json # Assuming your messages are JSON as in ClientController

RABBITMQ_HOST = '127.0.0.1' # Or your RabbitMQ server address
QUEUE_NAME = 'tpar3.dev'
VHOST = '/'
# If you have authentication, add credentials
# CREDENTIALS = pika.PlainCredentials('guest', 'guest') 
# PARAMETERS = pika.ConnectionParameters(RABBITMQ_HOST, virtual_host=VHOST, credentials=CREDENTIALS)
PARAMETERS = pika.ConnectionParameters(RABBITMQ_HOST, virtual_host=VHOST)


def callback(ch, method, properties, body):
    print(f" [x] Received message from queue '{QUEUE_NAME}':")
    print(f"  Delivery Tag: {method.delivery_tag}")
    print(f"  Properties: {properties}")
    try:
        # Attempt to decode as JSON if that's what you expect
        message_content = json.loads(body.decode('utf-8'))
        print(f"  Body (JSON decoded): {json.dumps(message_content, indent=4)}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        print(f"  Body (raw bytes as string, may be binary): {body!r}")
    
    # IMPORTANT: Acknowledge the message so RabbitMQ removes it from the queue
    # If you don't ack, and auto_ack is false (default for basic_get), 
    # the message will be re-queued when this consumer disconnects.
    # ch.basic_ack(delivery_tag=method.delivery_tag) 
    # For just peeking without consuming permanently, you might basic_reject or basic_nack with requeue=True
    # or simply don't acknowledge and let them re-queue upon script exit.
    # For permanent consumption for debugging, ack is needed.
    # If your script is just for peeking a few, you can choose not to ack.
    # However, for basic_get, messages are delivered unacknowledged and remain in queue until acked or rejected.
    
    # For basic_get, we typically fetch one by one. If using basic_consume, this callback would be different.
    # This script will fetch one message then exit. To get all 4, you'd loop.

connection = pika.BlockingConnection(PARAMETERS)
channel = connection.channel()

# Ensure the queue exists (optional, but good practice)
# It must match the existing queue's properties. OpenTAKServer declares it as non-durable.
channel.queue_declare(queue=QUEUE_NAME, durable=False) 

print(f"[*] Waiting for messages in queue '{QUEUE_NAME}'. To exit press CTRL+C")

# Using basic_get to retrieve messages one by one
# Set auto_ack=False if you want to manually acknowledge (recommended for control)
# Set auto_ack=True if you want messages to be acked as soon as they are delivered by RabbitMQ (simpler for quick peeking)
# For just peeking, you might not want to ack them so they stay for the real consumer.
# If auto_ack=False, the message remains "unacked" in the queue until ch.basic_ack, ch.basic_nack, or ch.basic_reject.

message_count = 0
MAX_MESSAGES_TO_GET = 4 # Get up to 4 messages, or fewer if queue is smaller

print(f"[*] Attempting to retrieve up to {MAX_MESSAGES_TO_GET} messages...")

for i in range(MAX_MESSAGES_TO_GET):
    method_frame, properties, body = channel.basic_get(queue=QUEUE_NAME, auto_ack=False) 
    if method_frame:
        print(f"\n--- Message {message_count + 1} (Delivery Tag: {method_frame.delivery_tag}) ---")
        try:
            # Attempt to decode as JSON if that's what you expect
            message_content = json.loads(body.decode('utf-8'))
            print(f"  Properties: {properties}")
            print(f"  Body (JSON decoded): {json.dumps(message_content, indent=4)}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            print(f"  Properties: {properties}")
            print(f"  Body (raw bytes as string, may be binary): {body!r}")
        
        message_count += 1
        # To PEEK and RE-QUEUE the message for the intended consumer:
        if method_frame.delivery_tag:
            channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=True)
            print(f"  [i] Message with delivery tag {method_frame.delivery_tag} re-queued.")
        # To CONSUME and REMOVE the message permanently:
        # if method_frame.delivery_tag:
        #     channel.basic_ack(delivery_tag=method_frame.delivery_tag)
        #     print(f"  [i] Message with delivery tag {method_frame.delivery_tag} acknowledged and removed.")
    else:
        print("[*] No more messages in queue.")
        break

print(f"\n[*] Retrieved {message_count} message(s).")
connection.close()
print("[*] Connection closed.")
