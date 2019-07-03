import copy


class BaseMixin:
    """
    Base mixin
    """
    datetime_format = "%Y%m%d_%H%M%S"

    @staticmethod
    def format(error: bool=False, msg: str='',
               result: (list, dict)=None, **kwargs):
        """
        Response answer
        :param error: has error or not
        :param msg: message (usually using for error description )
        :param result: request result
        :param kwargs: additional arguments
        :return:
        """
        response = copy.deepcopy(kwargs)
        response.update({
            'result': result,
            'error': error,
            'msg': msg})

        return response
