"""Official messaging channel adapters for TijaraGuard."""

from .base import (
    ChannelAdapter,
    ChannelInboundEvent,
    ChannelRegistry,
    ChannelShieldTransport,
    ChannelStatusEvent,
    OutboundSendResult,
    detect_preferred_language,
    normalize_receipt_id,
)
from .chatwoot import ChatwootAdapter
from .telegram import TelegramBotAdapter
from .webhook import GenericWebhookAdapter
from .whatsapp import WhatsAppCloudAdapter

__all__ = [
    "ChannelAdapter",
    "ChannelInboundEvent",
    "ChannelRegistry",
    "ChannelShieldTransport",
    "ChannelStatusEvent",
    "ChatwootAdapter",
    "GenericWebhookAdapter",
    "OutboundSendResult",
    "TelegramBotAdapter",
    "WhatsAppCloudAdapter",
    "detect_preferred_language",
    "normalize_receipt_id",
]
