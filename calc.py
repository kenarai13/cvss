def convert_cvss31_to_cvss40(cvss31_vector):
    """
    Конвертирует вектор CVSS 3.1 в CVSS 4.0.
    :param cvss31_vector: Строка с вектором CVSS 3.1, например: "AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    :return: Строка с вектором CVSS 4.0
    """
    # Словари для соответствий метрик
    attack_vector = {"L": "L", "A": "A", "N": "N", "P": "P"}
    attack_complexity = {"L": ("L", "N"), "H": ("L", "P")}
    privileges_required = {"N": "N", "L": "L", "H": "H"}
    user_interaction = {"N": "N", "R": "R"}
    scope = {"U": ("N", "N", "N"), "C": ("C", "C", "C")}
    impact = {"N": "N", "L": "L", "H": "H"}

    try:
        # Разбираем входной вектор
        cvss31_elements = dict(item.split(":") for item in cvss31_vector.split("/")[1:])

        # Проверяем обязательные метрики
        required_metrics = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        if not required_metrics.issubset(cvss31_elements.keys()):
            raise ValueError("Вектор CVSS 3.1 содержит недостаточные метрики.")

        # Конвертация метрик
        av = f"AV:{attack_vector[cvss31_elements['AV']]}"  # Attack Vector
        ac, at = attack_complexity[cvss31_elements['AC']]  # Attack Complexity & Attack Technique
        pr = f"PR:{privileges_required[cvss31_elements['PR']]}"  # Privileges Required
        ui = f"UI:{user_interaction[cvss31_elements['UI']]}"  # User Interaction
        vc = f"VC:{impact[cvss31_elements['C']]}"  # Confidentiality Impact
        vi = f"VI:{impact[cvss31_elements['I']]}"  # Integrity Impact
        va = f"VA:{impact[cvss31_elements['A']]}"  # Availability Impact
        sc, si, sa = scope[cvss31_elements['S']]  # Scope Changes

        # Формируем итоговый вектор CVSS 4.0
        cvss40_vector = f"CVSS:4.0/{av}/AC:{ac}/AT:{at}/{pr}/{ui}/{vc}/{vi}/{va}/SC:{sc}/SI:{si}/SA:{sa}"
        return cvss40_vector

    except Exception as e:
        return f"Ошибка: {e}"


# Основная программа
if __name__ == "__main__":
    print("Введите вектор CVSS 3.1:")
    cvss31_input = input().strip()
    cvss40_output = convert_cvss31_to_cvss40(cvss31_input)
    print("Результат конвертации:")
    print(cvss40_output)
