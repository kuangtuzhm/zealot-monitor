package com.zealot.monitor.filter;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.AbstractConfigurationFilter;
import org.jasig.cas.client.util.RequestURIFilter;
import org.jasig.cas.client.util.ServletUtil;
import org.jasig.cas.client.validation.Assertion;

import com.appleframework.config.core.PropertyConfigurer;
import com.zealot.model.entity.Operator;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.Map;

public class BossFilter extends AbstractConfigurationFilter {
		
	public static String SESSION_USER_KEY = "CAS_USER";
	public static String SESSION_OPERATOR = "CAS_OPERATOR";
	public static String SESSION_CAS_KEY  = "_const_cas_assertion_";
	
	/**
     * 过滤地址集合
     */
	protected RequestURIFilter excludeFilter;
	
    /**
     * 过滤地址
     */
	private String exclusions = null;

	public void destroy() {
	}
	
	public boolean isExcluded(String path) {
        // 如果指定了excludes，并且当前requestURI匹配任何一个exclude pattern，
        // 则立即放弃控制，将控制还给servlet engine。
        // 但对于internal path，不应该被排除掉，否则internal页面会无法正常显示。
        if (excludeFilter != null && excludeFilter.matches(path)) {
        	return true;
        }
        return false;
    }
	
	/**
	 * 过滤逻辑：首先判断单点登录的账户是否已经存在本系统中，
	 * 如果不存在使用用户查询接口查询出用户对象并设置在Session中
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		
		String path = ServletUtil.getResourcePath(httpRequest);
        if (isExcluded(path)) {
            filterChain.doFilter(request, response);
            return;
        }
		// _const_cas_assertion_是CAS中存放登录用户名的session标志
		Object object = httpRequest.getSession().getAttribute(SESSION_CAS_KEY);
		
		if (object != null) {
			Operator<Integer>  operator = (Operator<Integer>)httpRequest.getSession().getAttribute(SESSION_OPERATOR);
			if(null == operator) {
				Assertion assertion = (Assertion) object;
				String username = assertion.getPrincipal().getName();
				//AuthorizeService authorizeService = (AuthorizeService)SpringUtility.getBean("authorizeService");
				
				/*UserService userService = (UserService)SpringUtility.getBean("userService");
				user = userService.getByUsername(username);*/
				AttributePrincipal principal = (AttributePrincipal) httpRequest.getUserPrincipal(); 
				Map<String, Object> attributes = principal.getAttributes();
				
				operator = new Operator<Integer>();
				
				operator.setId(Integer.parseInt(attributes.get("uid").toString()));
				operator.setAccount(username);
				operator.setName(attributes.get("uname").toString());
				httpRequest.getSession().setAttribute(SESSION_OPERATOR, operator);	
			}
		}
		filterChain.doFilter(request, response);
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//获取需要过滤拦截地址
		String s = filterConfig.getInitParameter("exclusions");
        setExclusions(s);
        String filterExclusions = exclusions  + "," + PropertyConfigurer.getValue("filter.exclusions");
		excludeFilter = new RequestURIFilter(filterExclusions);
	}
	
	public void setExclusions(String exclusions) {
		this.exclusions = exclusions;
	}
		
}

