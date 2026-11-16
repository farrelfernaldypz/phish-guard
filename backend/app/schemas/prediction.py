from pydantic import BaseModel, ConfigDict, Field, field_validator
from ..services.url_validator import MAX_URL_LENGTH

class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def url_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("URL cannot be empty.")
        return value

