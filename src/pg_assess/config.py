from pydantic import Field\nfrom pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_env: str = "local"
    assessment_api_key: str = "change-me"
    assessment_data_dir: str = "./reports"
    http_timeout_seconds: float = Field(default=8.0, ge=1.0, le=20.0)\n    assessment_allowed_staging_hosts: str = ""
    user_agent: str = "PesaGuardSecurityAssessment/0.1"

settings = Settings()
