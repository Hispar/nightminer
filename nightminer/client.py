import json
import threading
import logging


class SimpleJsonRpcClient(object):
    """Simple JSON-RPC client.
  
      To use this class:
        1) Create a sub-class
        2) Override handle_reply(self, request, reply)
        3) Call connect(socket)
  
      Use self.send(method, params) to send JSON-RPC commands to the server.
  
      A new thread is created for listening to the connection; so calls to handle_reply
      are synchronized. It is safe to call send from withing handle_reply.
    """

    class ClientException(Exception):
        pass

    class RequestReplyException(Exception):
        def __init__(self, message, reply, request=None):
            Exception.__init__(self, message)
            self._reply = reply
            self._request = request

        request = property(lambda s: s._request)
        reply = property(lambda s: s._reply)

    class RequestReplyWarning(RequestReplyException):
        """Sub-classes can raise this to inform the user of JSON-RPC server issues."""
        pass

    def __init__(self):
        self._socket = None
        self._lock = threading.RLock()
        self._rpc_thread = None
        self._message_id = 1
        self._requests = dict()

    def _handle_incoming_rpc(self):
        data = ""
        while True:
            # Get the next line if we have one, otherwise, read and block
            if '\n' in data:
                (line, data) = data.split('\n', 1)
            else:
                chunk = self._socket.recv(1024)
                data += chunk.decode('utf-8')
                continue

            logging.info('JSON-RPC Server > ' + line)

            # Parse the JSON
            try:
                reply = json.loads(line)
            except Exception as e:
                logging.error("JSON-RPC Error: Failed to parse JSON %r (skipping)" % line)
                continue

            try:
                request = None
                with self._lock:
                    if 'id' in reply and reply['id'] in self._requests:
                        request = self._requests[reply['id']]
                    self.handle_reply(request=request, reply=reply)
            except self.RequestReplyWarning as e:
                output = e.message
                if e.request:
                    output += '\n  ' + e.request
                output += '\n  ' + e.reply
                logging.error(output)

    def handle_reply(self, request, reply):
        # Override this method in sub-classes to handle a message from the server
        raise self.RequestReplyWarning('Override this method')

    def send(self, method, params):
        """Sends a message to the JSON-RPC server"""

        if not self._socket:
            raise self.ClientException('Not connected')

        request = dict(id=self._message_id, method=method, params=params)
        message = json.dumps(request)

        with self._lock:
            self._requests[self._message_id] = request
            self._message_id += 1
            self._socket.send((message + '\n').encode())

        logging.info('JSON-RPC Server < ' + message)

        return request

    def connect(self, socket):
        """Connects to a remove JSON-RPC server"""

        if self._rpc_thread:
            raise self.ClientException('Already connected')

        self._socket = socket

        self._rpc_thread = threading.Thread(target=self._handle_incoming_rpc)
        self._rpc_thread.daemon = True
        self._rpc_thread.start()
