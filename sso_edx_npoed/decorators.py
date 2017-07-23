# coding: utf-8
def comment_client_user_npoed_dec(user_cls):
    """
    Этот декоратор нужно повесить на класс User в lms.lib.comment_client.user
    Он добавляет поле full_name в список посылаемых данных в cs_comments_service
    """
    _accessible_fields = list(user_cls.accessible_fields)
    _accessible_fields.append("full_name")

    _updatable_fields = list(user_cls.updatable_fields)
    _updatable_fields.append("full_name")

    class CommentClientNpoedUser(user_cls):
        updatable_fields = _updatable_fields
        accessible_fields = _accessible_fields

        @classmethod
        def from_django_user(cls, user):
            return cls(id=str(user.id),
                       external_id=str(user.id),
                       username=user.username,
                       full_name=(user.get_full_name() or user.username))

    return CommentClientNpoedUser
