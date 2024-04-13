package com.technokratos.security.security.evaluator;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication auth, Object domainObject, Object permission) {
        if ((auth == null) || (domainObject == null) || !(permission instanceof String)) {
            return false;
        }

        String domainType = domainObject.toString().toUpperCase();
        return checkPrivilege(auth, domainType, permission.toString().toUpperCase());
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        if ((auth == null) || (targetType == null) || !(permission instanceof String)) {
            return false;
        }

        return checkPrivilege(auth, targetType.toUpperCase(), permission.toString().toUpperCase());
    }

    private boolean checkPrivilege(Authentication auth, String targetType, String permission) {
        for (GrantedAuthority grantedAuth : auth.getAuthorities()) {
            String authString = grantedAuth.getAuthority();
            if (authString.startsWith(targetType) && authString.contains(permission))
                return true;
        }
        return false;
    }
}
