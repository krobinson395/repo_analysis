import threading
import queue
import time

def producer(queue, data):
    for item in data:
        queue.put(item)
        time.sleep(1)

def consumer(queue, id):
    while True:
        item = queue.get()
        if item is None:
            break
        print(f"{id} Consumed: {item}")
        time.sleep(1)

# Create a shared queue
shared_queue = queue.Queue()

# Start producer and consumer threads
data_to_send = [1, 2, 3, 4, 5]
producer_thread = threading.Thread(target=producer, args=(shared_queue, data_to_send))
consumer1_thread = threading.Thread(target=consumer, args=(shared_queue, 1))

producer_thread.start()
consumer1_thread.start()

# Signal the consumer to stop
shared_queue.put(None)
consumer1_thread.join()


# Wait for the producer to finish producing
producer_thread.join()
