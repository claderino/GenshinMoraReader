# Generates an original Mora-inspired gold coin icon and packs a multi-size .ico
Add-Type -AssemblyName System.Drawing

$dir = "J:\GenshinReader\assets"
New-Item -ItemType Directory -Force $dir | Out-Null

function Draw-Mora {
    param([int]$size, [string]$path)

    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.ScaleTransform($size / 256.0, $size / 256.0)

    $darkRim  = [System.Drawing.Color]::FromArgb(255, 176, 108, 12)
    $goldHi   = [System.Drawing.Color]::FromArgb(255, 255, 224, 131)
    $goldLo   = [System.Drawing.Color]::FromArgb(255, 226, 158, 26)
    $innerDisc = [System.Drawing.Color]::FromArgb(255, 247, 206, 91)
    $motif    = [System.Drawing.Color]::FromArgb(255, 148, 94, 4)

    # outer dark rim
    $g.FillEllipse((New-Object System.Drawing.SolidBrush($darkRim)), 8, 8, 240, 240)

    # main disc, radial gold gradient
    $rect = New-Object System.Drawing.Rectangle(16, 16, 224, 224)
    $gp = New-Object System.Drawing.Drawing2D.GraphicsPath
    $gp.AddEllipse($rect)
    $brush = New-Object System.Drawing.Drawing2D.PathGradientBrush($gp)
    $brush.CenterColor = $goldHi
    $brush.SurroundColors = @($goldLo)
    $g.FillEllipse($brush, $rect)

    # inner ring
    $penRing = New-Object System.Drawing.Pen($darkRim, 7)
    $g.DrawEllipse($penRing, 44, 44, 168, 168)

    # inner lighter disc
    $g.FillEllipse((New-Object System.Drawing.SolidBrush($innerDisc)), 56, 56, 144, 144)

    # swirl motif
    $penSwirl = New-Object System.Drawing.Pen($motif, 20)
    $penSwirl.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $penSwirl.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawArc($penSwirl, 78, 78, 100, 100, 20, 200)
    $g.DrawArc($penSwirl, 108, 108, 40, 40, 200, 260)

    # center dot
    $g.FillEllipse((New-Object System.Drawing.SolidBrush($motif)), 118, 118, 20, 20)

    # top-left shine
    $g.FillEllipse((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(90, 255, 255, 255))), 40, 36, 60, 34)

    $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

Draw-Mora 256 "$dir\icon256.png"
Draw-Mora 48  "$dir\icon48.png"
Draw-Mora 32  "$dir\icon32.png"
Draw-Mora 16  "$dir\icon16.png"

# Pack PNGs into a multi-image .ico (PNG-embedded entries, Vista+)
$sizes = @(256, 48, 32, 16)
$pngs = @()
foreach ($s in $sizes) {
    $pngs += ,[System.IO.File]::ReadAllBytes("$dir\icon$s.png")
}

$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)

# ICONDIR
$bw.Write([uint16]0)      # reserved
$bw.Write([uint16]1)      # type: icon
$bw.Write([uint16]$sizes.Count)

$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $len = $pngs[$i].Length
    $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))  # width
    $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))  # height
    $bw.Write([byte]0)      # palette
    $bw.Write([byte]0)      # reserved
    $bw.Write([uint16]1)    # color planes
    $bw.Write([uint16]32)   # bits per pixel
    $bw.Write([uint32]$len) # data size
    $bw.Write([uint32]$offset)
    $offset += $len
}
foreach ($png in $pngs) { $bw.Write($png) }
$bw.Flush()

[System.IO.File]::WriteAllBytes("$dir\icon.ico", $ms.ToArray())
$bw.Dispose(); $ms.Dispose()

Get-ChildItem $dir | Select-Object Name, Length
