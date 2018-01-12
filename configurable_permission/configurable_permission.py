from trac.config import ListOption
from trac.core import Component, ExtensionPoint, TracError, implements
from trac.perm import IPermissionGroupProvider, IPermissionPolicy, \
    IPermissionRequestor, PermissionSystem
from trac.ticket.model import Ticket
from trac.util.compat import set
from trac.web.chrome import Chrome
from trac.ticket.query import Query, QuerySyntaxError, QueryValueError

class ConfigurablePermissionPolicy(Component):
    implements(IPermissionRequestor, IPermissionPolicy)

    def __init__(self):
        self.wiki_perm, self.ticket_perm = self._build_permission_config()

    def get_permission_actions(self):
        result = []
        for opt_name, opt_value in self.config.options('configuratable-permission'):
            if opt_value == 'enabled':
                result.append(opt_name.upper())
        return result

    def check_permission(self, action, username, resource, user_perm):
        
        result = None
        
        if resource is None:
            return None
        
        elif resource.realm == 'ticket':
            for perm in self.ticket_perm:
                if (perm.action == action or perm.action == '*' or perm.action == '') \
                        and resource.id is not None:

                    flag = False
                    if perm.rule == '' or perm.rule == '*':
                        flag = True
                    else:
                        query_string = 'id=' + str(resource.id) + '&' + perm.rule
                        try:
                            query = Query.from_string(self.env, query_string)
                        except QuerySyntaxError as e:
                            raise TracError(e)
                        try:
                            tickets = query.execute()
                        except QueryValueError as e:
                            raise TracError(e)
                        if len(tickets) > 0:
                            flag = True

                    if flag:
                        return self._should_allow(perm, user_perm)

        elif resource.realm == 'wiki':
            for perm in self.wiki_perm:
                if perm.action == action or perm.action == '*' or perm.action == '':
                    if perm.wiki_name == '' or perm.wiki_name == '*' or perm.wiki_name == resource.id:
                        return self._should_allow(perm, user_perm)

        return result

    def _should_allow(self, perm, user_perm):
        if perm.permission == '' or perm.permission == '*' or self._has_permission_simple(user_perm.username, perm.permission):
            if perm.result.lower() in ['allow', 'allow-only']:
                return True
            elif perm.result.lower() == 'deny':
                return False
            elif perm.result.lower() in ['pass', 'pass-only']:
                return None
        else:
            if perm.result.lower() in ['allow-only', 'pass-only']:
                return False
        return None

    def _has_permission_simple(self, user, perm):
        ps = PermissionSystem(self.env)
        users = ps.get_users_with_permission(perm)
        return user in users

    def _build_permission_config(self):
        wiki_perm = []
        ticket_perm = []

        for opt_name, opt_value in self.config.options('configuratable-permission-rules'):
            values = map(lambda x: x.strip(), opt_value.split(','))
            if len(values) != 5:
                self.log.warn('ConfigurablePermissionPolicy: invalid syntax for rule "' + opt_name + '", ignore')
                continue
            if not values[4].lower() in ['allow', 'allow-only', 'deny', 'pass', 'pass-only']:
                self.log.warn('ConfigurablePermissionPolicy: invalid result for rule "' + opt_name + '", default to pass')
                values[4] = 'pass'
            if values[0] == 'ticket':
                ticket_perm.append(ConfigurablePermissionPolicy.ConfigurableTicketPermission(*values))
            elif values[0] == 'wiki':
                wiki_perm.append(ConfigurablePermissionPolicy.ConfigurableWikiPermission(*values))
            else:
                self.log.warn('ConfigurablePermissionPolicy: not supported type for rule "' + opt_name + '", default to pass')

        return wiki_perm, ticket_perm

    class ConfigurableWikiPermission(object):
        def __init__(self, name, action, wiki_name, permission, result):
            self.name = name
            self.wiki_name = wiki_name
            self.permission = permission
            self.action = action
            self.result = result.lower()

    class ConfigurableTicketPermission(object):
        def __init__(self, name, action, rule, permission, result):
            self.rule = rule
            self.name = name
            self.permission = permission
            self.action = action
            self.result = result.lower()

            