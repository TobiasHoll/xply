import enum
import os
import re
import select
import socket
import subprocess
import sys
import time
import threading
import typing

# Timeouts
class timeout_error(RuntimeError):
    '''An operation timed out'''
    pass

# Generic connections
class connection:
    '''A generic connection for talking to pretty much anything'''
    _raw_send_type = typing.Callable[[typing.Any, bytes], None]
    _raw_recv_type = typing.Callable[[typing.Any, float], bytes]
    _raw_eoi_type  = typing.Callable[[typing.Any], None]
    _logging_type  = typing.Callable[[bytes], None]

    def __init__(self,
                 raw_recv: _raw_recv_type = None,
                 raw_send: _raw_send_type = None,
                 raw_eoi:  _raw_eoi_type = None,
                 on_recv:  _logging_type = None,
                 on_send:  _logging_type = None):
        '''Create a new connection with the specified read and write primitives'''
        self._raw_recv = raw_recv
        self._raw_send = raw_send
        self._raw_eoi = raw_eoi
        self.buffer = b''
        self.on_recv = on_recv
        self.on_send = on_send

    # Baseline receive and send primitives based on the raw arguments to __init__
    def recv(self, timeout: float = None) -> bytes:
        '''Receive data. If the timeout expires without data,
           returns an empty bytes object. If timeout is None,
           blocks until data is available.'''
        if self._raw_recv is not None:
            data = self._raw_recv(timeout)
            if self.on_recv is not None:
                self.on_recv(data)
            return data
        else:
            raise RuntimeError('Connection is not readable')

    def send(self, data: bytes):
        '''Sends all the data in the buffer, if necessary in multiple packets'''
        if self._raw_send is not None:
            if self.on_send is not None:
                self.on_send(data)
            return self._raw_send(data)
        else:
            raise RuntimeError('Connection is not writable')

    # Buffered receive functions that adjust a cumulative timeout
    def _recv_into_buffer_timed(self, timeout: float = None) -> float:
        '''Receives data into the internal buffer, and returns the adjusted
           timeout after the receive.'''
        if timeout is None:
            self.buffer += self.recv(timeout)
        else:
            start = time.time()
            self.buffer += self.recv(timeout)
            end = time.time()
            duration = end - start
            timeout = max(0, timeout - duration)
        return timeout

    def _recvline_timed(self,
                        timeout: float = None,
                        keepends: bool = False,
                        newline: bytes = b'\n') -> (bytes, float):
        '''Reads one line (from the buffer or otherwise), and adjusts the
           timeout for every call to `recv`.'''
        while newline not in self.buffer:
            timeout = self._recv_into_buffer_timed(timeout)
        end = self.buffer.index(newline) + len(newline)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        if not keepends:
            result = result[:-len(newline)]
        return result, timeout

    # Utility functions
    def recv_n(self,
               count: int,
               timeout: float = None) -> bytes:
        '''Receives exactly `count` bytes.'''
        while len(self.buffer) < count:
            timeout = self._recv_into_buffer_timed(timeout)
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def recv_for(self,
                 timeout: float) -> bytes:
        '''Receives data for the specified time. The timeout must not
           be None.'''
        if timeout is None:
            raise ValueError('recv_for: Timeout must not be None')
        try:
            while True:
                timeout = self._recv_into_buffer_timed(timeout)
        except timeout_error:
            result, self.buffer = self.buffer, b''
            return result

    def recv_pred(self,
                  predicate: typing.Callable,
                  timeout: float = None) -> bytes:
        '''Receives data until the predicate is true. This will call the
           predicate for every byte that is received. The timeout is shared
           across all receive requests made.'''
        end = 0
        while not predicate(self.buffer[:end]):
            if end > len(self.buffer):
                # Buffer is over, need more data
                timeout = self._recv_into_buffer_timed(timeout)
            end += 1
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def recv_regex(self,
                   pattern: bytes,
                   timeout: float = None,
                   flags: re.RegexFlag = 0,
                   exact: bool = False,
                   return_match: bool = False) -> typing.Union[bytes, re.Match]:
        '''Receives data until the regex matches the buffer. This will
           evaluate the regex for every packet that is received, but only
           return data up to match.end(). If `return_match` is True, the match
           object is returned instead. If `exact` is True, uses `re.match`
           over `re.search`.'''
        compiled = re.compile(pattern, flags)
        function = compiled.match if exact else compiled.search
        while True:
            match = function(self.buffer)
            if not match:
                # No match, need more data
                timeout = self._recv_into_buffer_timed(timeout)
            else:
                # Found a match
                end = match.end()
                before_end, self.buffer = self.buffer[:end], self.buffer[end:]
                return match if return_match else before_end

    def recv_contains(self,
                      items: typing.Union[bytes, typing.Sequence[bytes]],
                      timeout: float = None) -> bytes:
        '''Receives bytes until the buffer contains at least one of the items
           (if it is a list of byte strings, otherwise just the item itself).'''
        if isinstance(items, bytes):
            items = [items]
        pred = lambda data: any(item in data for item in items)
        return self.recv_pred(predicate=pred, timeout=timeout)

    def recv_until(self,
                   delimiters: typing.Sequence[int],
                   timeout: float = None,
                   keep: bool = True) -> bytes:
        '''Receives data until encountering one of the delimiters. If `keep`
           is False, remove it from the output before returning.'''
        pred = lambda data: len(data) > 0 and data[-1] in delimiters
        result = self.recv_pred(pred, timeout)
        return result[:-1] if not keep else result

    def recvline(self,
                 timeout: float = None,
                 keepends: bool = False,
                 newline: bytes = b'\n') -> bytes:
        '''Receives one line of data. If `keepends` is False, chop off the
           newline characters. You can specify what type of newline to listen
           for (e.g. b'\r\n' or b'\n') through the `newline` argument.'''
        return self._recvline_timed(timeout=timeout, keepends=keepends, newline=newline)[0]

    def recvline_pred(self,
                      predicate: typing.Callable[[bytes], typing.Any],
                      timeout: float = None,
                      keepends: bool = False,
                      newline: bytes = b'\n') -> bytes:
        '''Receives lines until a line is encountered that fulfils the
           predicate. Note that newlines are chopped before the predicate
           is invoked.'''
        while True:
            line, timeout = self._recvline_timed(timeout=timeout, keepends=keepends, newline=newline)
            match = predicate(line)
            if match:
                return line

    def recvline_regex(self,
                       pattern: bytes,
                       timeout: float = None,
                       flags: re.RegexFlag = 0,
                       exact: bool = False,
                       return_match: bool = False,
                       keepends: bool = False,
                       newline: bytes = b'\n') -> typing.Union[bytes, re.Match]:
        '''Receives lines until a line is encountered that matches the
           specified regular expression. Note that newlines are chopped
           before the matching takes place. If `exact` is True, uses
           `re.match` instead of `re.search`. If `return_match` is true,
           returns the match object instead of the raw data.'''
        compiled = re.compile(pattern, flags)
        function = compiled.match if exact else compiled.search
        while True:
            line, timeout = self._recvline_timed(timeout=timeout, keepends=keepends, newline=newline)
            match = function(line)
            if match:
                # Found a match
                return match if return_match else line

    def recvline_contains(self,
                          items: typing.Union[bytes, typing.Sequence[bytes]],
                          timeout: float = None,
                          keepends: bool = False,
                          newline: bytes = b'\n') -> bytes:
        '''Receives lines until a line is encountered that contains at least
           one of the items (if it is a list of byte strings, otherwise just
           the item itself). Again, newlines are chopped before the matching
           takes place if `keepends` is False'''
        if isinstance(items, bytes):
            items = [items]
        pred = lambda data: any(item in data for item in items)
        return self.recvline_pred(predicate=pred, timeout=timeout, keepends=keepends, newline=newline)

    def recvline_startswith(self,
                            start: bytes,
                            timeout: float = None,
                            keepends: bool = False,
                            newline: bytes = b'\n') -> bytes:
        '''Receives lines until a line is encountered that starts with the
           specified content.'''
        pred = lambda data: data.startswith(start)
        return self.recvline_pred(predicate=pred, timeout=timeout, keepends=keepends, newline=newline)

    def recvline_endswith(self,
                          end: bytes,
                          timeout: float = None,
                          keepends: bool = False,
                          newline: bytes = b'\n') -> bytes:
        '''Receives lines until a line is encountered that ends with the
           specified content. Newlines are chopped before the matching if
           `keepends` is False.'''
        pred = lambda data: data.endswith(end)
        return self.recvline_pred(predicate=pred, timeout=timeout, keepends=keepends, newline=newline)

    def recvlines_n(self,
                    count: int,
                    timeout: float = None,
                    keepends: bool = False,
                    newline: bytes = b'\n') -> typing.List[bytes]:
        '''Receives exactly `count` lines of input.'''
        lines = []
        for _ in range(count):
            line, timeout = self._recvline_timed(timeout=timeout, keepends=keepends, newline=newline)
            lines.append(line)
        return lines

    def recvlines_for(self,
                      timeout: float,
                      keepends: bool = False,
                      newline: bytes = b'\n') -> typing.List[bytes]:
        '''Receives lines for the specified time.
           The timeout must not be None.'''
        if timeout is None:
            raise ValueError('recvlines_for: Timeout must not be None')
        lines = []
        try:
            while True:
                line, timeout = self._recvline_timed(timeout=timeout, keepends=keepends, newline=newline)
                lines.append(line)
        except timeout_error:
            return lines

    # Send functions
    def sendline(self,
                 data: bytes,
                 newline: bytes = b'\n') -> None:
        '''Sends the data followed by a newline'''
        return self.send(data + newline)

    # "recv_all"-style functions
    def recv_all(self) -> bytes:
        '''Receives all remaining data until the socket closes.'''
        data = b''
        while True:
            try:
                data += self.recv()
            except BrokenPipeError:
                return data

    def recvlines_all(self,
                      keepends: bool = False,
                      newline: bytes = b'\n') -> typing.List[bytes]:
        '''Receives lines until the socket closes.'''
        lines = []
        while True:
            try:
                lines.append(self.recvline(timeout=None, keepends=keepends, newline=newline))
            except BrokenPipeError:
                return lines

    # Interactivity
    def end_of_input(self):
        '''Indicates that no more input will be sent. This may close underlying
           files or streams.'''
        self._raw_send = None # Disable sending
        if self._raw_eoi:
            self._raw_eoi()

    def stream(self, output_stream: typing.Any = sys.stdout.buffer):
        '''Streams the received data onto a file-like object or
           into another connection.'''
        self.end_of_input()
        if isinstance(output_stream, connection):
            send_fn = output_stream.send
        else:
            send_fn = output_stream.write

        while True:
            try:
                send_fn(self.recv())
            except BrokenPipeError:
                break

    def interactive(self,
                    unbuffer_termios: bool = False,
                    receive_interval: float = 0.05) -> bool:
        '''Allows the user to interact with the connection through
           standard input and output. By default, buffering on stdin
           is disabled on our side, but the shell may still buffer
           input (consider using `unbuffer` or `stdbuf` to fix this).
           If desired, set `unbuffer_termios` to True to use the
           `termios` module to disable terminal buffering. Returns
           True if the user canceled interactive mode by pressing
           Ctrl+C, returns False on exceptions (i.e. BrokenPipeError)'''

        do_exit = threading.Event()

        # Spin off a thread that receives data in a loop.
        def do_receive():
            # Receive data until EOF
            while not do_exit.is_set():
                try:
                    data = self.recv_for(receive_interval)
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
                except BrokenPipeError:
                    do_exit.set()
                    break

        receive_thread = threading.Thread(target=do_receive)
        receive_thread.daemon = True # Do not stop the program from exiting while this is running
        receive_thread.start()

        # We need stdin to be unbuffered
        fd = os.dup(sys.stdin.fileno())

        if unbuffer_termios:
            import termios
            import tty
            tattr = termios.tcgetattr(fd)
            tty.setcbreak(fd, termios.TCSANOW)

        fatal_exception = True
        with os.fdopen(fd, 'rb', buffering=0) as unbuffered_stdin:
            # Read input from stdin and send it
            try:
                while not do_exit.is_set():
                    data = unbuffered_stdin.read(1)
                    if data:
                        if unbuffer_termios:
                            # This disables echo, so we need to write ourselves
                            sys.stdout.buffer.write(data)
                        try:
                            self.send(data)
                        except BrokenPipeError:
                            do_exit.set()
                            break
            except KeyboardInterrupt:
                fatal_exception = False
                do_exit.set()

        # Join the thread
        while receive_thread.is_alive():
            receive_thread.join(timeout=0.25)
        return fatal_exception



# Process connections

class process_output_mode(enum.Enum):
    MERGE       = 0
    STDOUT_ONLY = 1
    STDERR_ONLY = 2

    def map(self, output_fd):
        mapping = {
            process_output_mode.MERGE:       (output_fd,          output_fd),
            process_output_mode.STDOUT_ONLY: (output_fd,          subprocess.DEVNULL),
            process_output_mode.STDERR_ONLY: (subprocess.DEVNULL, output_fd),
        }
        return mapping[self]

class process_connection(connection):
    '''A connection to a local process'''
    _buffer_size = 4096
    _internal_timeout = 0.05
    _exit_timeout = 0.1

    def __init__(self, command: typing.Union[typing.List[str], str], output_mode: process_output_mode = process_output_mode.MERGE, **other_kwargs):
        '''Starts a local process and connects to its input and output streams'''
        super().__init__(self._recv_impl, self._send_impl, self._eoi_impl, **other_kwargs)

        # Start the process
        self.command = command
        self.output_mode = output_mode

        in_read, self.input = os.pipe()
        self.output, out_write = os.pipe()

        stdout_mode, stderr_mode = output_mode.map(out_write)
        self.process = subprocess.Popen(command, bufsize=0, stdin=in_read, stdout=stdout_mode, stderr=stderr_mode)

        os.close(in_read)
        os.close(out_write)

    def close(self):
        '''Close the connection and terminate the process'''
        self.process.terminate()
        self.process.wait(process_connection._exit_timeout)
        self.process.kill()
        self.process.communicate() # Clear buffers
        self.process = None

        if self.input:
            os.close(self.input)
        os.close(self.output)
        self.input = None
        self.output = None

    def __enter__(self):
        '''Empty wrapper for `with`'''
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        '''Clean up and close the connection'''
        self.close()

    # Send and receive primitives
    def _send_impl(self, data: bytes) -> None:
        '''Send data.'''
        os.write(self.input, data)

    def _select(self, timeout: float = 0) -> bool:
        '''Checks whether we have data to receive'''
        try:
            ready, _, error = select.select([self.output], [], [self.output], timeout)
            if self.output in error:
                raise BrokenPipeError('File descriptor entered error state')
            else:
                return self.output in ready
        except ValueError:
            # Invalid file
            raise BrokenPipeError('Cannot select on invalid file descriptor')

    def _check_exited(self) -> bool:
        '''Checks whether the process has exited'''
        return self.process.poll() is not None

    def _recv_impl(self, timeout: float = None) -> bytes:
        '''Receive data. If timeout is None, block until we receive data.'''
        try:
            if self._check_exited():
                raise BrokenPipeError('Connection closed')

            # Select or poll the socket
            if timeout is None:
                while not self._check_exited() and not self._select(process_connection._internal_timeout):
                    pass
            else:
                if not self._check_exited() and not self._select(timeout):
                    raise timeout_error('Socket not ready after timeout')

            # Read data while there is any
            data = b''
            while self._select():
                next_data = os.read(self.output, process_connection._buffer_size)

                if len(next_data) <= 0 and len(data) <= 0:
                    raise BrokenPipeError('Connection closed')
                elif len(next_data) <= 0:
                    return data

                data += next_data
            return data
        except BrokenPipeError:
            raise # Do not wrap this like other OSErrors
        except OSError as underlying:
            # Error while reading
            raise BrokenPipeError('Error while reading') from underlying

    def _eoi_impl(self) -> None:
        '''Closes the input stream'''
        if self.input:
            os.close(self.input)
            self.input = None



# Network connections

class network_protocol(enum.Enum):
    '''Supported network protocols for remote connections'''
    TCP  = 0
    UDP  = 1
    # TODO: TLS  = 2
    # TODO: DTLS = 3
    # TODO: SSL wrapping

    def socket_type(self):
        mapping = {
            network_protocol.TCP: socket.SOCK_STREAM,
            network_protocol.UDP: socket.SOCK_DGRAM,
        }
        return mapping[self]

class ip_version(enum.Enum):
    '''Constants for IPv4 and IPv6'''
    Any  = 0
    IPv4 = 1
    IPv6 = 2

    def address_family(self):
        mapping = {
            ip_version.Any:  socket.AF_UNSPEC,
            ip_version.IPv4: socket.AF_INET,
            ip_version.IPv6: socket.AF_INET6,
        }
        return mapping[self]

class network_error(RuntimeError):
    '''Any network errors in remote connections'''
    pass

class network_connection(connection):
    '''A remote network connection'''
    _buffer_size = 4096

    def __init__(self, host: str, port: int, protocol: network_protocol = network_protocol.TCP, timeout: float = None, ip: ip_version = ip_version.Any, **other_kwargs):
        '''Creates a new connection to the specified remote target.'''
        super().__init__(self._recv_impl, self._send_impl, self._eoi_impl, **other_kwargs)
        self.host = host
        self.port = port
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip

        # Translate the protocol to a socket protocol recognized by the kernel
        socket_type = self.protocol.socket_type()
        address_family = self.ip_version.address_family()

        # Find an address for the remote host
        addresses = socket.getaddrinfo(self.host, self.port, address_family, socket_type, 0)
        if addresses == []:
            raise network_error('Could not resolve address for {host}:{port}'.format(host=self.host, port=self.port))

        # Unpack the result
        address_family, socket_type, socket_proto, canonical_name, address = addresses[0]

        # Create the socket
        sock = socket.socket(address_family, socket_type, socket_proto)
        if not sock:
            raise network_error('Could not open socket for {host}:{port}'.format(host=self.host, port=self.port))

        # Set timeout and connect
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        sock.connect(address)

        # Store the socket directly
        self._socket = sock

    def close(self):
        '''Close the connection'''
        # Close the socket
        self.socket.close()
        self._socket = None

    def __enter__(self):
        '''Empty wrapper for `with`'''
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        '''Clean up and close the connection'''
        self.close()

    # Socket accessor that validates whether we actually opened the socket
    @property
    def socket(self):
        '''The underlying socket. Only use this if the connection is open'''
        if not self._socket:
            # Socket is closed
            message = 'Cannot access remote_connection.socket - connection is closed!'
            try:
                import inspect
                stack = inspect.stack()
                if stack is not None:
                    for frame in stack[::-1]:
                        if frame.filename == __file__:
                            caller = frame.function
                            message = 'Invalid call to remote_connection.{} - connection is closed!'.format(caller)
                            break
            except ImportError:
                pass # Do not update the message if we cannot import inspect.
            raise RuntimeErrors(message)
        return self._socket

    # Send and receive primitives
    def _send_impl(self, data: bytes) -> None:
        '''Send data.'''
        self.socket.sendall(data)

    def _select(self, timeout: float = 0) -> bool:
        '''Checks whether we have data to receive'''
        try:
            ready, _, error = select.select([self.socket], [], [self.socket], timeout)
            if self.socket in error:
                raise BrokenPipeError('Socket entered error state')
            else:
                return self.socket in ready
        except ValueError:
            # Invalid socket
            raise BrokenPipeError('Cannot select on socket')

    def _recv_impl(self, timeout: float = None) -> bytes:
        '''Receive data. If timeout is None, block until we receive data.'''
        try:
            # Select or poll the socket
            if timeout is None:
                while not self._select(None):
                    pass
            else:
                if not self._select(timeout):
                    raise timeout_error('Socket not ready after timeout')

            # Read data while there is any
            data = b''
            while self._select():
                next_data = self.socket.recv(network_connection._buffer_size)

                if len(next_data) <= 0 and len(data) <= 0:
                    raise BrokenPipeError('Connection closed')
                elif len(next_data) <= 0:
                    return data

                data += next_data
            return data
        except BrokenPipeError:
            raise # Do not wrap this like other OSErrors
        except OSError as underlying:
            # Error while reading
            raise BrokenPipeError('Error while reading') from underlying

    def _eoi_impl(self) -> None:
        '''Closes the input stream'''
        self.socket.shutdown(socket.SHUT_WR)
