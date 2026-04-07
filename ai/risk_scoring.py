class RiskScorer:
    def __init__(self, rule_weight=0.6, ai_weight=0.4):
        self.rule_weight = rule_weight
        self.ai_weight = ai_weight

    def compute_risk(self, rule_threats, ai_anomaly_score):
        if rule_threats:
            max_rule_risk = max(score for _, score in rule_threats) / 100.0
        else:
            max_rule_risk = 0.0

        combined = self.rule_weight * max_rule_risk + self.ai_weight * ai_anomaly_score
        return min(100, int(combined * 100))

    def threat_level(self, risk_score):
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        else:
            return "LOW"