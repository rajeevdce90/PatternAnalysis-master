$file = "uploads/cloudtrail.json"
$targetIndex = "aws"
$datatype = "aws_logs"
$url = "http://localhost:5000/upload"

Write-Host "Uploading file $file to $url..."
$form = @{
    file = Get-Item -Path $file
    target_index = $targetIndex
    datatype = $datatype
}

try {
    $response = Invoke-RestMethod -Uri $url -Method Post -Form $form
    Write-Host "Upload successful!"
    $response | ConvertTo-Json
} catch {
    Write-Host "Error occurred: $_"
} 