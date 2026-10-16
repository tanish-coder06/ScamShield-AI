def generate_explanation(message: str, is_scam: bool) -> dict:
    """
    Generate risk explanations, warning signs, and safety advice.

    These are rule-based indicators, not proof that a message is fraudulent.
    """

    text = message.lower()

    red_flags = []
    recommendations = []

    # Detect urgency and pressure.
    urgency_phrases = [
        "immediately",
        "urgent",
        "act now",
        "within 24 hours",
        "account will be blocked",
        "account suspended",
        "last chance",
        "limited time",
        "तुरंत",
        "जल्दी करें",
        "अभी करें",
        "खाता बंद",
    ]

    if any(phrase in text for phrase in urgency_phrases):
        red_flags.append(
            "Urgency or pressure: the message may be pushing you "
            "to act before verifying the claim."
        )

        recommendations.append(
            "Pause before acting. Verify the claim independently "
            "instead of following the message's instructions."
        )

    # Detect financial rewards and prizes.
    reward_phrases = [
        "you won",
        "winner",
        "cash prize",
        "claim your prize",
        "free money",
        "lottery",
        "reward",
        "इनाम",
        "लॉटरी",
        "जीत गए",
        "इनाम पाएं",
    ]

    if any(phrase in text for phrase in reward_phrases):
        red_flags.append(
            "Unexpected reward or prize: unsolicited prize claims "
            "can be used to lure victims."
        )

        recommendations.append(
            "Confirm the prize directly with the official organization. "
            "Do not pay a fee or share sensitive information to claim it."
        )

    # Detect requests for sensitive information.
    sensitive_phrases = [
        "otp",
        "one time password",
        "password",
        "pin number",
        "bank details",
        "card details",
        "cvv",
        "upi pin",
        "पासवर्ड",
        "ओटीपी",
        "पिन नंबर",
    ]

    if any(phrase in text for phrase in sensitive_phrases):
        red_flags.append(
            "Sensitive information mentioned: check whether the sender "
            "is asking you to disclose credentials or financial details."
        )

        recommendations.append(
            "Never share your OTP, password, card security code, "
            "or UPI PIN with someone contacting you unexpectedly."
        )

    # Detect links.
    has_link = (
        "http://" in text
        or "https://" in text
        or "www." in text
    )

    if has_link:
        red_flags.append(
            "A web link is present. Its destination has not been "
            "independently verified by this message scanner."
        )

        recommendations.append(
            "Avoid opening unexpected links. Visit the organization's "
            "official website or app directly instead."
        )

    # Detect threats or account suspension language.
    threat_phrases = [
        "account blocked",
        "account suspended",
        "legal action",
        "police case",
        "arrest warrant",
        "account बंद",
        "खाता बंद",
        "गिरफ्तार",
    ]

    if any(phrase in text for phrase in threat_phrases):
        red_flags.append(
            "Threatening or intimidating language may be intended "
            "to pressure the recipient."
        )

        recommendations.append(
            "Do not rely on contact details provided in the message. "
            "Contact the organization through a verified channel."
        )

    # Generate recommendations based on the model's prediction.
    if is_scam:
        risk_summary = (
            "The machine-learning model classified this message as "
            "potentially fraudulent based on patterns learned during training."
        )

        recommendations.insert(
            0,
            "Treat this message as suspicious until you independently "
            "verify the sender and the claim."
        )

        recommendations.extend([
            "Do not send money or disclose personal or financial information.",
            "If the message claims to be from an organization, contact it "
            "using its official app, website, or a trusted phone number.",
        ])

    else:
        risk_summary = (
            "The machine-learning model classified this message as "
            "legitimate. This does not guarantee that it is safe."
        )

        recommendations.extend([
            "Check the sender's identity if the message requests money "
            "or personal information.",
            "Avoid sharing passwords, OTPs, or banking credentials.",
        ])

    # Add a fallback if no rules were triggered.
    if not red_flags:
        red_flags.append(
            "No warning signs from the current rule set were identified. "
            "This does not prove the message is safe."
        )

    # Remove duplicate recommendations while preserving order.
    recommendations = list(dict.fromkeys(recommendations))

    return {
        "risk_summary": risk_summary,
        "red_flags": red_flags,
        "recommendations": recommendations,
        "safety_notice": (
            "These indicators are guidance, not proof of fraud. "
            "The model can make mistakes, and links have not been opened "
            "or independently checked."
        ),
    }