terraform {
  backend "s3" {
    bucket       = "REPLACE_WITH_OWN_STATE_BUCKET"
    key          = "coin/terraform.tfstate"
    region       = "eu-north-1"
    encrypt      = true
    use_lockfile = true
  }
}
