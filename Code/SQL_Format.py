"""Simple program to format sql results outside of the main program"""


def format_result(sql_result):
    result = str(sql_result)
    result.replace("[", "")
    result.replace("]", "")
    result.replace("'", "")
    result.replace("(", "")
    result.replace(")", "")

    return result
