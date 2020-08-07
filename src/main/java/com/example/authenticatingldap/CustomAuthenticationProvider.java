package com.example.authenticatingldap;

import com.sun.org.apache.xpath.internal.operations.Bool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.*;
import java.util.logging.Logger;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private Logger log = Logger.getLogger(String.valueOf(CustomAuthenticationProvider.class));

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        log.info("email : " + username);
        log.info("password : " + password);

        if (isLdapRegistred(username, password)) {
            // use the credentials
            // and authenticate against the third-party system
            return new UsernamePasswordAuthenticationToken(
                    username, password, new ArrayList<>());
        } else {
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    boolean isLdapRegistred(String username, String password) {

        String ldap_server_url = "ldap://server.ipademo.local";
        boolean result = false;
        String GRANTED_GROUP = "sysadmin"; // specific groups (access granted)

        try {
            Hashtable<String, String> env = new Hashtable<String, String>();
            String Securityprinciple = "uid=" + username + ",cn=users,cn=accounts,dc=ipademo,dc=local";
            String usersContainer = "cn=users,cn=accounts,dc=ipademo,dc=local";

            Set<String> cn_group = new HashSet<String>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldap_server_url);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, Securityprinciple);
            env.put(Context.SECURITY_CREDENTIALS, password);

            // Create the initial context
            DirContext ctx = new InitialDirContext(env);

            // SearchControls for filtering LDAP
            SearchControls ctls = new SearchControls();
            String[] attrIDs = { "uid", "cn", "memberOf" };
            ctls.setReturningAttributes(attrIDs);
            ctls.setSearchScope(SearchControls.ONELEVEL_SCOPE);;

            // Enumerate LDAP Attributes
            NamingEnumeration answer = ctx.search(usersContainer, "(objectclass=person)", ctls);

            while (answer.hasMore()) {
                SearchResult rslt = (SearchResult) answer.next();
                Attributes attrs = rslt.getAttributes();
                String groups = attrs.get("memberOf").toString(); // get attribute memberOf user
                String uid = attrs.get("uid").toString().split(": ")[1]; // get user
                System.out.println("User: "+uid);
                String groupname = groups.split(":")[1];
                System.out.println("Groups: "+groupname+"\n");
                String[] splitCn = groupname.split(", ");

                // Get all intended user groups
                if (uid.equals(username)) {
                    for(int i=0; i<splitCn.length; i++) {
                        cn_group.add(splitCn[i].substring(splitCn[i].indexOf('=')+1, splitCn[i].indexOf(',')));
                    }
                    System.out.println(cn_group);
                    break;
                }
            }

            result = false;
            if (ctx != null)
                ctx.close();

            if (result = ctx != null && cn_group.contains(GRANTED_GROUP)){
                System.out.println(123);
                result = true;
                System.out.println(result);
            }

            return result;
        }

        catch (Exception e) {
            System.out.println("Sorry something's wrong");
            return result ;
        }
    }
}