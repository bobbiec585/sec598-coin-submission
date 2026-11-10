provider "aws" {
  region = "eu-north-1"

  default_tags {
    tags = {
      Project   = "sec598-coin"
      ManagedBy = "terraform"
      Owner     = "rob"
    }
  }
}
