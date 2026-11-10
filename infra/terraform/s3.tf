resource "aws_s3_bucket" "ansible_transfer" {
  bucket_prefix = "sec598-coin-ansible-"
  force_destroy = var.deployment_suffix != ""
  tags = {
    Name = "sec598-coin-ansible-transfer"
  }
}

resource "aws_s3_bucket_versioning" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id

  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
output "ansible_transfer_bucket" {
  value = aws_s3_bucket.ansible_transfer.bucket
}
