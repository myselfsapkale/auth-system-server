interface UserType {
    user_first_name: string,
    user_type: string,
    user_last_name: string,
    user_email: string,
    user_phone: string,
    provider: string,
    password: string,
    created_on?: string,
    updated_on?: string,
    is_active?: 0 | 1
}


interface TokenUserDetail { 
    user_id: number, 
    user_type: string 
}


interface AuthCookie {
    user_id: number,
    user_type: string,
    refresh_token: string,
    access_token: string
}


interface GoogleAuthUser {
    user_first_name: string,
    user_type: string,
    user_last_name: string,
    user_email: string,
    provider: string,
    is_active: 1
}


export { UserType, TokenUserDetail, AuthCookie, GoogleAuthUser }