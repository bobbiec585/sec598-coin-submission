resource "aws_vpc" "coin" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "sec598-coin-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.coin.id
  cidr_block              = "10.20.10.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "sec598-coin-public"
  }
}

resource "aws_internet_gateway" "coin" {
  vpc_id = aws_vpc.coin.id

  tags = {
    Name = "sec598-coin-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.coin.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.coin.id
  }

  tags = {
    Name = "sec598-coin-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "target" {
  name        = "sec598-coin-target${local.name_suffix}"
  description = "Security group for the SEC598 coin target"
  vpc_id      = aws_vpc.coin.id

  egress {
    description = "Allow outbound IPv4"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sec598-coin-target"
  }
}
