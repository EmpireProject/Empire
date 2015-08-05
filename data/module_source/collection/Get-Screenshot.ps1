function Get-Screenshot 
{
    Add-Type -Assembly System.Windows.Forms
    $ScreenBounds = [Windows.Forms.SystemInformation]::VirtualScreen
    $ScreenshotObject = New-Object Drawing.Bitmap $ScreenBounds.Width, $ScreenBounds.Height
    $DrawingGraphics = [Drawing.Graphics]::FromImage($ScreenshotObject)
    $DrawingGraphics.CopyFromScreen( $ScreenBounds.Location, [Drawing.Point]::Empty, $ScreenBounds.Size)
    $DrawingGraphics.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $ScreenshotObject.save($ms, [Drawing.Imaging.ImageFormat]::Png)
    $ScreenshotObject.Dispose()
    [convert]::ToBase64String($ms.ToArray())
}
Get-Screenshot