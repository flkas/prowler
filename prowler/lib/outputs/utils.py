from typing import Any, Tuple

from prowler.config.config import aws_logo, azure_logo, gcp_logo, square_logo_img
from prowler.lib.logger import logger


def get_provider_identity_and_logo(provider: Any) -> Tuple[str, str]:
    """
    Build an identity string and logo URL based on the provider metadata.

    Args:
        provider: The provider object associated with the current run.

    Returns:
        tuple[str, str]: A tuple with a markdown-friendly identity string and a logo image URL.
    """
    identity = ""
    logo = aws_logo
    try:
        if provider.type == "aws":
            identity = f"AWS Account *{provider.identity.account}*"
        elif provider.type == "gcp":
            identity = f"GCP Projects *{', '.join(provider.project_ids)}*"
            logo = gcp_logo
        elif provider.type == "azure":
            printed_subscriptions = []
            for key, value in provider.identity.subscriptions.items():
                printed_subscriptions.append(f"- *{key}: {value}*\n")
            identity = f"Azure Subscriptions:\n{''.join(printed_subscriptions)}"
            logo = azure_logo
        # TODO: support kubernetes, m365, github, additional providers
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    return identity, logo


def build_summary_title(identity: str, stats: dict) -> str:
    """
    Compose the common greeting/summary string used in chat integrations.

    Args:
        identity: Provider identity string (e.g., AWS account or Azure subscriptions).
        stats: Aggregated statistics produced by extract_findings_statistics.

    Returns:
        str: Human-friendly title text.
    """
    try:
        return (
            "Hey there 👋 \n I'm *Prowler*, _the handy multi-cloud security tool_ "
            ":cloud::key:\n\n I have just finished the security assessment on your "
            f"{identity} with a total of *{stats['findings_count']}* findings."
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return ""


def get_prowler_avatar() -> str:
    """
    Return the default Prowler avatar/logo used across chat integrations.
    """
    return square_logo_img


def unroll_list(listed_items: list, separator: str = "|") -> str:
    """
    Unrolls a list of items into a single string, separated by a specified separator.

    Args:
        listed_items (list): The list of items to be unrolled.
        separator (str, optional): The separator to be used between the items. Defaults to "|".

    Returns:
        str: The unrolled string.

    Examples:
        >>> unroll_list(['apple', 'banana', 'orange'])
        'apple | banana | orange'

        >>> unroll_list(['apple', 'banana', 'orange'], separator=',')
        'apple, banana, orange'

        >>> unroll_list([])
        ''
    """
    unrolled_items = ""
    if listed_items:
        for item in listed_items:
            if not unrolled_items:
                unrolled_items = f"{item}"
            else:
                if separator == "|":
                    unrolled_items = f"{unrolled_items} {separator} {item}"
                else:
                    unrolled_items = f"{unrolled_items}{separator} {item}"

    return unrolled_items


def unroll_tags(tags: list) -> dict:
    """
    Unrolls a list of tags into a dictionary.

    Args:
        tags (list): A list of tags.

    Returns:
        dict: A dictionary containing the unrolled tags.

    Examples:
        >>> tags = [{"key": "name", "value": "John"}, {"key": "age", "value": "30"}]
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = [{"Key": "name", "Value": "John"}, {"Key": "age", "Value": "30"}]
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = [{"key": "name"}]
        >>> unroll_tags(tags)
        {'name': ''}

        >>> tags = [{"Key": "name"}]
        >>> unroll_tags(tags)
        {'name': ''}

        >>> tags = [{"name": "John", "age": "30"}]
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = []
        >>> unroll_tags(tags)
        {}

        >>> tags = {"name": "John", "age": "30"}
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = ["name", "age"]
        >>> unroll_tags(tags)
        {'name': '', 'age': ''}
    """
    if tags and tags != [{}] and tags != [None] and tags != []:
        if isinstance(tags, dict):
            return tags
        if isinstance(tags[0], str) and len(tags) > 0:
            return {tag: "" for tag in tags}
        if "key" in tags[0]:
            return {item["key"]: item.get("value", "") for item in tags}
        elif "Key" in tags[0]:
            return {item["Key"]: item.get("Value", "") for item in tags}
        else:
            return {key: value for d in tags for key, value in d.items()}
    return {}


def unroll_dict(dict: dict, separator: str = "=") -> str:
    """
    Unrolls a dictionary into a string representation.

    Args:
        dict (dict): The dictionary to be unrolled.

    Returns:
        str: The unrolled string representation of the dictionary.

    Examples:
        >>> my_dict = {'name': 'John', 'age': 30, 'hobbies': ['reading', 'coding']}
        >>> unroll_dict(my_dict)
        'name: John | age: 30 | hobbies: reading, coding'
    """

    unrolled_items = ""
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
        if not unrolled_items:
            unrolled_items = f"{key}{separator}{value}"
        else:
            unrolled_items = f"{unrolled_items} | {key}{separator}{value}"

    return unrolled_items


def unroll_dict_to_list(dict: dict) -> list:
    """
    Unrolls a dictionary into a list of key-value pairs.

    Args:
        dict (dict): The dictionary to be unrolled.

    Returns:
        list: A list of key-value pairs, where each pair is represented as a string.

    Examples:
        >>> my_dict = {'name': 'John', 'age': 30, 'hobbies': ['reading', 'coding']}
        >>> unroll_dict_to_list(my_dict)
        ['name: John', 'age: 30', 'hobbies: reading, coding']
    """

    dict_list = []
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
            dict_list.append(f"{key}:{value}")
        else:
            dict_list.append(f"{key}:{value}")

    return dict_list


def parse_json_tags(tags: list) -> dict[str, str]:
    """
    Parses a list of JSON tags and returns a dictionary of key-value pairs.

    Args:
        tags (list): A list of JSON tags.

    Returns:
        dict: A dictionary containing the parsed key-value pairs from the tags.

    Examples:
        >>> tags = [
        ...     {"Key": "Name", "Value": "John"},
        ...     {"Key": "Age", "Value": "30"},
        ...     {"Key": "City", "Value": "New York"}
        ... ]
        >>> parse_json_tags(tags)
        {'Name': 'John', 'Age': '30', 'City': 'New York'}
    """

    dict_tags = {}
    if tags and tags != [{}] and tags != [None]:
        for tag in tags:
            if "Key" in tag and "Value" in tag:
                dict_tags[tag["Key"]] = tag["Value"]
            else:
                dict_tags.update(tag)

    return dict_tags


def parse_html_string(str: str) -> str:
    """
    Parses a string and returns a formatted HTML string.

    This function takes an input string and splits it using the delimiter " | ".
    It then formats each element of the split string as a bullet point in HTML format.

    Args:
        str (str): The input string to be parsed.

    Returns:
        str: The formatted HTML string.

    Example:
        >>> parse_html_string("item1 | item2 | item3")
        '\n&#x2022;item1\n\n&#x2022;item2\n\n&#x2022;item3\n'
    """
    string = ""
    for elem in str.split(" | "):
        if elem:
            string += f"\n&#x2022;{elem}\n"

    return string
