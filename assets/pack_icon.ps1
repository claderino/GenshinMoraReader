# Packs the official Mora icon (UI_ItemIcon_202, downloaded from enka.network)
# into a multi-size .ico
Add-Type -AssemblyName System.Drawing

$dir = "J:\GenshinReader\assets"
$src = "$env:TEMP\opencode\mora_dl.png"

$source = [System.Drawing.Image]::FromFile($src)

function Save-Scaled {
    param([int]$size, [string]$path)
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($source, 0, 0, $size, $size)
    $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

$sizes = @(256, 48, 32, 16)
foreach ($s in $sizes) {
    if ($s -eq 256) {
        # keep the pristine original for the largest size
        Copy-Item $src "$dir\icon$s.png" -Force
    } else {
        Save-Scaled $s "$dir\icon$s.png"
    }
}
$source.Dispose()

# Pack PNGs into a multi-image .ico (PNG-embedded entries, Vista+)
$pngs = @()
foreach ($s in $sizes) {
    $pngs += ,[System.IO.File]::ReadAllBytes("$dir\icon$s.png")
}

$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)

$bw.Write([uint16]0)
$bw.Write([uint16]1)
$bw.Write([uint16]$sizes.Count)

$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $len = $pngs[$i].Length
    $dim = [byte]$(if ($s -ge 256) { 0 } else { $s })
    $bw.Write($dim)
    $bw.Write($dim)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([uint16]1)
    $bw.Write([uint16]32)
    $bw.Write([uint32]$len)
    $bw.Write([uint32]$offset)
    $offset += $len
}
foreach ($png in $pngs) { $bw.Write($png) }
$bw.Flush()

[System.IO.File]::WriteAllBytes("$dir\icon.ico", $ms.ToArray())
$bw.Dispose(); $ms.Dispose()

Get-ChildItem $dir -Filter icon* | Select-Object Name, Length
