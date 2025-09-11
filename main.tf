provider "aws" {
  region = "ap-south-1"
}

provider "aws" {
  region     = "us-east-1"
  alias      = "nvirginia"
}

resource "aws_s3_bucket" "crc-bucket-tf" {
  bucket = "crc-bucket-tf"

  tags = {
    Name = "crc-bucket-tf"
  }
}

resource "aws_s3_bucket" "crc-bucket-tf_root" {
  bucket = "crc-bucket-tf-root"

  tags = {
    Name = "crc-bucket-tf-root"
  }
}

resource "aws_s3_bucket_versioning" "crc-bucket-tf-ver" {
  bucket = aws_s3_bucket.crc-bucket-tf.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "crc-bucket-tf-lc" {
    depends_on = [ aws_s3_bucket_versioning.crc-bucket-tf-ver ]
    
    bucket = aws_s3_bucket.crc-bucket-tf.id
    rule {
        id = "crc"

        noncurrent_version_expiration {
            noncurrent_days = 90
        }
        
        filter {}

        status = "Enabled"

        noncurrent_version_transition {
            newer_noncurrent_versions = 1
            noncurrent_days = 30
            storage_class = "STANDARD_IA"
        }
    }
}

resource "aws_s3_bucket_public_access_block" "crc-bucket-tf-pab" {
  bucket = aws_s3_bucket.crc-bucket-tf.id

  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "crc-bucket-tf-ssec" {
  bucket = aws_s3_bucket.crc-bucket-tf.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_website_configuration" "crc_bucket_tf_webcon" {
  bucket = aws_s3_bucket.crc-bucket-tf_root.id

  redirect_all_requests_to {
    host_name = "www.yr-portfolio.com"
    protocol = "https"
  }
}

resource "aws_cloudfront_origin_access_identity" "crc_bucket_tf_oai" {
  comment = "OAI for yr-portfolio.com"
}

data "aws_iam_policy_document" "crc_bucket_tf_s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.crc-bucket-tf.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.crc_bucket_tf_oai.iam_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "crc_bucket_tf_policy" {
  bucket = aws_s3_bucket.crc-bucket-tf.id
  policy = data.aws_iam_policy_document.crc_bucket_tf_s3_policy.json
}

resource "aws_acm_certificate" "crc_bucket_tf_acm" {
  domain_name = "yr-portfolio.com"
  subject_alternative_names = ["*.yr-portfolio.com"]
  provider = aws.nvirginia
  validation_method = "DNS"
  key_algorithm = "RSA_2048"
  tags = {
    Name = "CRC"
  }
}

data "aws_route53_zone" "crc_bucket_tf_53z" {
  name = "yr-portfolio.com"
  private_zone = false
}

resource "aws_route53_record" "crc_bucket_tf_53r" {
  for_each = {
    for dvo in aws_acm_certificate.crc_bucket_tf_acm.domain_validation_options : dvo.domain_name => {
      name    = dvo.resource_record_name
      record  = dvo.resource_record_value
      type    = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.crc_bucket_tf_53z.zone_id
}

resource "aws_acm_certificate_validation" "crc_bucket_tf_acmv" {
  provider = aws.nvirginia
  certificate_arn         = aws_acm_certificate.crc_bucket_tf_acm.arn
  validation_record_fqdns = [for record in aws_route53_record.crc_bucket_tf_53r : record.fqdn]
}

locals {
  s3_origin_id = "myS3Origin"
  s3_origin_id_root = "myS3Origin_root"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  depends_on = [aws_acm_certificate_validation.crc_bucket_tf_acmv]
  origin {
    domain_name = aws_s3_bucket.crc-bucket-tf.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.crc_bucket_tf_oai.cloudfront_access_identity_path
    }
  }
  
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  
  aliases = ["www.yr-portfolio.com"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    cache_policy_id = aws_cloudfront_cache_policy.caching_disabled.id

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.crc_bucket_tf_acm.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_cloudfront_cache_policy" "caching_disabled" {
  name        = "CachingDisabledPolicy"
  comment     = "Disables caching"
  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_distribution" "s3_distribution_root" {
  depends_on = [aws_acm_certificate_validation.crc_bucket_tf_acmv]
  origin {
    domain_name = aws_s3_bucket_website_configuration.crc_bucket_tf_webcon.website_endpoint
    origin_id   = local.s3_origin_id_root
    custom_origin_config {
      origin_protocol_policy = "http-only"
          http_port  = "80"
          https_port = "443"
          origin_ssl_protocols = ["TLSv1.2"]
    }
  }
  
  enabled             = true
  is_ipv6_enabled     = true
  provider = aws.nvirginia
  
  aliases = ["yr-portfolio.com"]

  default_cache_behavior {
    cache_policy_id        = aws_cloudfront_cache_policy.caching_disabled.id
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = local.s3_origin_id_root
    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.crc_bucket_tf_acm.arn
    ssl_support_method = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_route53_record" "crc_bucket_tf_www" {
  zone_id = data.aws_route53_zone.crc_bucket_tf_53z.zone_id
  name    = "www.yr-portfolio.com"
  type    = "A"

  alias {
    name = aws_cloudfront_distribution.s3_distribution.domain_name
    zone_id = aws_cloudfront_distribution.s3_distribution.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "crc_bucket_tf_root" {
  zone_id = data.aws_route53_zone.crc_bucket_tf_53z.zone_id
  name    = "yr-portfolio.com"
  type    = "A"

  alias {
    name = aws_cloudfront_distribution.s3_distribution_root.domain_name
    zone_id = aws_cloudfront_distribution.s3_distribution_root.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_dynamodb_table_item" "crc_dynamodb_tf_viewcount" {
  table_name = aws_dynamodb_table.crc_dynamodb_tf.name
  hash_key   = "id"

  item = <<ITEM
{
  "id": {"S": "General"},
  "viewsCount": {"N": "1"}
}
ITEM
}

resource "aws_dynamodb_table" "crc_dynamodb_tf" {
  name           = "websiteviewscount"
  billing_mode = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
  tags = {
    "name" = "CRC_tf"
  }
}

# IAM role for Lambda execution
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "crc_iam_tf" {
  name               = "lambda_execution_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Package the Lambda function code
data "archive_file" "crc_arc_tf" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.py"
  output_path = "${path.module}/lambda/function.zip"
}

# Lambda function
resource "aws_lambda_function" "crc_lambda_tf" {
  filename         = data.archive_file.crc_arc_tf.output_path
  function_name    = "crc_lambda_function"
  role             = aws_iam_role.crc_iam_tf.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.crc_arc_tf.output_base64sha256

  runtime = "python3.13"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
    }
  }

  tags = {
    Environment = "production"
    Application = "crc"
  }
}

resource "aws_lambda_function_url" "crc_lambda_function_url" {
  function_name      = aws_lambda_function.crc_lambda_tf.function_name
  authorization_type = "NONE"
}

resource "aws_api_gateway_rest_api" "crc_api" {
  name = "crc_api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "crc_api_resource" {
  parent_id = aws_api_gateway_rest_api.crc_api.root_resource_id
  path_part = "CRC"
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
}

resource "aws_api_gateway_method" "crc_api_method" {
  authorization = "NONE"
  http_method = "POST"
  resource_id = aws_api_gateway_resource.crc_api_resource.id
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
}

resource "aws_api_gateway_integration" "crc_api_integration" {
  http_method = aws_api_gateway_method.crc_api_method.http_method
  resource_id = aws_api_gateway_resource.crc_api_resource.id
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
  type = "AWS_PROXY" # Does this change lambda proxy integration to true? Important, as it NEEDS tio be false.
  integration_http_method = "POST"
  uri = aws_lambda_function.crc_lambda_tf.invoke_arn
}

resource "aws_api_gateway_deployment" "crc_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
  # stage_name is deprecated, use a separate aws_api_gateway_stage resource instead
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.crc_api_resource.id,
      aws_api_gateway_method.crc_api_method.id,
      aws_api_gateway_integration.crc_api_integration.id
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [ 
    aws_api_gateway_integration.crc_api_integration
   ]
}

resource "aws_api_gateway_stage" "crc_api_stage" {
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
  deployment_id = aws_api_gateway_deployment.crc_api_deployment.id
  stage_name = "dev"
}

# Might be redundant if we already have iam role, check once
resource "aws_lambda_permission" "crc_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crc_lambda_tf.function_name
  principal = "apigateway.amazonaws.com"
  statement_id = "AllowExecutionFromAPIGateway"
  source_arn = "${aws_api_gateway_rest_api.crc_api.execution_arn}/*/POST/CRC"
}

resource "aws_api_gateway_method_response" "crc_api_methodresponse" {
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
  resource_id = aws_api_gateway_resource.crc_api_resource.id
  http_method = aws_api_gateway_method.crc_api_method.http_method
  status_code = "200"
  response_models = {
    "application/json" = "Empty"
  }
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true
    "method.response.header.Access-Control-Allow-Methods"     = true
    "method.response.header.Access-Control-Allow-Origin"      = true
  }
}

resource "aws_api_gateway_integration_response" "crc_api_integrationresponse" {
  rest_api_id = aws_api_gateway_rest_api.crc_api.id
  resource_id = aws_api_gateway_resource.crc_api_resource.id
  http_method = aws_api_gateway_method.crc_api_method.http_method
  status_code = aws_api_gateway_method_response.crc_api_methodresponse.status_code
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST'"
    "method.response.header.Access-Control-Allow-Origin" = "'*'"
  }
}

output "crc_invoke_url" {
  value = aws_api_gateway_stage.crc_api_stage.invoke_url
}