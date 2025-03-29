# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(1)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    max_age = None
    
    # Find the X-Cached-Timestamp and Cache-Control headers
    for line in cacheData:
        if line.lower().startswith("x-cached-timestamp:"):
            cached_time = int(line.split(":")[1].strip())
        if line.lower().startswith("cache-control:") and "max-age=" in line.lower():
            max_age_part = line.lower().split("max-age=")[1]
            max_age = int(max_age_part.split(",")[0].strip())
    
    # Check if this is an image file based on content type
    is_image = False
    has_via_header = False
    for line in cacheData:
        if line.lower().startswith("content-type:") and "image/" in line.lower():
            is_image = True
        if line.lower().startswith("via:") and "python-proxy" in line.lower():
            has_via_header = True
    
    if is_image:
        # Handle image files by reopening in binary mode
        cacheFile.close()
        try:
            with open(cacheLocation, "rb") as binary_file:
                binary_data = binary_file.read()
                
                # Find the header/body boundary
                header_end = binary_data.find(b'\r\n\r\n')
                if header_end != -1:
                    # Split into headers and body
                    headers = binary_data[:header_end]
                    body = binary_data[header_end+4:]  # Skip \r\n\r\n
                    
                    # Convert headers to string for easier processing
                    headers_str = headers.decode('latin-1')
                    header_lines = headers_str.split('\r\n')
                    modified_headers = []
                    has_via = False
                    
                    # Process headers
                    for header in header_lines:
                        if header.lower().startswith('content-length:'):
                            # Update Content-Length to match actual body size
                            modified_headers.append(f'Content-Length: {len(body)}')
                        elif header.lower().startswith('via:') and 'python-proxy' in header.lower():
                            # Keep existing Via header
                            modified_headers.append(header)
                            has_via = True
                        elif header.lower().startswith('x-cached-timestamp:'):
                            # Skip internal timestamp header
                            continue
                        else:
                            modified_headers.append(header)
                    
                    # Add Via header only if not already present
                    if not has_via:
                        via_header = f"Via: 1.1 {proxyHost}:{proxyPort} (Python-Proxy)"
                        modified_headers.append(via_header)
                    
                    # Reconstruct the full response
                    header_block = '\r\n'.join(modified_headers).encode('latin-1')
                    clientSocket.sendall(header_block + b'\r\n\r\n' + body)
                    
                    # For debug
                    print('Sent image file from cache with Via header')
        except Exception as e:
            print(f"Error handling image file: {str(e)}")
            # Fall back to text-based handling if binary fails
            is_image = False
            cacheFile = open(cacheLocation, "r")
            cacheData = cacheFile.readlines()
    
    if not is_image:
        # Original text file handling
        # Find headers section and Content-Length
        headers = []
        body = []
        content_length_line = -1
        has_via = False
        in_headers = True
        
        for i, line in enumerate(cacheData):
            if in_headers:
                if line.strip() == "":
                    in_headers = False
                    headers.append(line)  # Add blank line to headers
                else:
                    if line.lower().startswith("content-length:"):
                        content_length_line = i
                    # Check for existing Via header
                    if line.lower().startswith("via:") and "python-proxy" in line.lower():
                        has_via = True
                    # Skip internal X-Cached-Timestamp header
                    if line.lower().startswith("x-cached-timestamp:"):
                        continue
                    headers.append(line)
            else:
                body.append(line)
        
        # Calculate actual body content length
        body_content = ''.join(body)
        body_bytes = body_content.encode()
        actual_length = len(body_bytes)
        
        # Update Content-Length if found
        if content_length_line != -1:
            headers[content_length_line] = f"Content-Length: {actual_length}\r\n"
        
        # Add Via header before the blank line only if not already present
        if not has_via:
            via_header = f"Via: 1.1 {proxyHost}:{proxyPort} (Python-Proxy)\r\n"
            headers.insert(len(headers) - 1, via_header)
        
        # Send headers then body
        for line in headers:
            clientSocket.send(line.encode())
        
        # Send body as a single block to avoid line ending issues
        clientSocket.send(body_bytes)
        
        # For compatibility with the rest of the code
        cacheData = "".join(headers + body)
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = f'GET {resource} HTTP/1.1'
      originServerRequestHeader = f'Host: {hostname}\r\nConnection: close'
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response = b''
      while True:
          data = originServerSocket.recv(BUFFER_SIZE)
          if not data:
              break
          response += data      
      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      # Add Via header to the response before sending to the client
      header_end = response.find(b'\r\n\r\n')
      if header_end != -1:
          headers = response[:header_end]
          body = response[header_end+4:]  # Skip \r\n\r\n
          
          # Check if this is an image file and if Via header is already present
          is_image = False
          has_via = False
          headers_str = headers.decode('latin-1', errors='replace')
          
          if "content-type: image/" in headers_str.lower():
              is_image = True
              print("Handling image file from origin server")
              
          if "via: 1.1" in headers_str.lower() and "python-proxy" in headers_str.lower():
              has_via = True
              
          # Add Via header only if not already present
          if not has_via:
              via_header = f"Via: 1.1 {proxyHost}:{proxyPort} (Python-Proxy)".encode('latin-1')
              modified_response = headers + b'\r\n' + via_header + b'\r\n\r\n' + body
          else:
              modified_response = response
          
          clientSocket.sendall(modified_response)
          
          # Also update response to store the modified version in cache
          response = modified_response
      else:
          # If we can't identify headers/body boundary, send as is
          clientSocket.sendall(response)
      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      # Check status code before caching
      status_line = response.decode('latin-1', errors='replace').split('\r\n')[0]
      status_code = int(status_line.split()[1])
      
      # Extract Cache-Control header and max-age
      headers_str = response.decode('latin-1', errors='replace').split('\r\n\r\n')[0]
      cache_control = None
      max_age = None
      should_cache = True
      
      # Look for Cache-Control header
      for line in headers_str.split('\r\n'):
          if line.lower().startswith('cache-control:'):
              cache_control = line
              # Extract max-age if present
              if 'max-age=' in line.lower():
                  max_age_part = line.lower().split('max-age=')[1]
                  max_age = int(max_age_part.split(',')[0].strip())
                  print(f"Found max-age directive: {max_age} seconds")
                  # Don't cache responses with max-age=0
                  if max_age == 0:
                      print("Response has max-age=0, not caching")
                      should_cache = False
                  
      # 301 responses MAY be cached by default
      # 302 responses MUST NOT be cached unless explicitly allowed
      # 404 responses SHOULD NOT be cached unless explicitly allowed
      if status_code in [302, 404]:
          # Check for cache-control headers that explicitly allow caching
          if cache_control and ('public' in cache_control.lower() or 'private' in cache_control.lower()):
              if should_cache:
                  cacheFile.write(response)
                  print(f'{status_code} response cached due to explicit cache-control directive')
          else:
              # Don't cache 302/404 responses without explicit caching directives
              print(f'{status_code} response not cached (requires explicit cache-control directive)')
              # Close and remove the cache file since we don't want to cache these responses
              cacheFile.close()
              try:
                  os.remove(cacheLocation)
                  print(f"Removed cache file for non-cacheable {status_code} response: {cacheLocation}")
              except OSError:
                  print(f"Failed to remove cache file: {cacheLocation}")
              should_cache = False
      else:
          if should_cache:
              cacheFile.write(response)
              print('Response cached')
          else:
              # Don't cache responses that shouldn't be cached
              cacheFile.close()
              try:
                  os.remove(cacheLocation)
                  print(f"Removed cache file for non-cacheable response: {cacheLocation}")
              except OSError:
                  print(f"Failed to remove cache file: {cacheLocation}")

      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
