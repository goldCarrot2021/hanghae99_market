# hanghae99_market

항해마켓 프로젝트입니다.
항해마켓은 판매자가 팔고싶은 물건을 등록할 수 있고 판매자와 구매자 간의 채팅기능을 사용할 수 있는 마켓입니다.

팀프로젝트의 백엔드 Repository 입니다.

[프론트엔드 Repository](https://github.com/Jinnycorn/hanghaemarket)

# 프로젝트 특징
- React, Spring을 기반으로 프로젝트 구현

    - 각 파트의 별도 Repository를 생성 후 작업
    - 프론트 : AWS S3 정적 호스팅
    - 백엔드 : AWS EC2 서버 호스팅
    - 빌드 후, S3와 EC2 연동

- 로그인 처리는 Jwt Token 방식으로 처리
- 게시글 작성 시 프론트에서 이미지 파일 형태로 받아 서버측에서 S3에 업로드 후 Url 돌려주는 방식

# 개요
- 명칭 : 항해마켓
- 개발 인원 : 5명 (프론트 2명[허민규,이지은], 백엔드 3명[김승욱,장현준,이은지])
- 개발 기간 : 2021.04.09 ~ 2021.04.22
- 개발 환경 : React, Spring ,
- 형상 관리 툴 : git
- 배포 환경 : AWS EC2, RDS(MYSQL), S3
- 일정 관리 툴 : [Notion](https://www.notion.so/3295a6aca9bd411b9cc7b5eadb9239cb?v=002a8755c0414bf388614efa88f27d8a)
- 사이트 : http://hanghaemarket.shop/
- 시연 영상 : https://www.youtube.com/watch?v=idAJS0OLPhY

# API 설계
![image](https://user-images.githubusercontent.com/70622731/115699219-6b95b400-a3a0-11eb-8c00-c4fcd0c3f420.png)
![image](https://user-images.githubusercontent.com/70622731/115699310-823c0b00-a3a0-11eb-94ca-103b24c80005.png)
![image](https://user-images.githubusercontent.com/70622731/115699379-9122bd80-a3a0-11eb-97e6-f309d5b65f61.png)
![image](https://user-images.githubusercontent.com/70622731/115699448-a0097000-a3a0-11eb-9efc-1780f32e21b8.png)


# 프로젝트 기능

- 로그인, 회원가입
- Jwt 토큰
- 소셜로그인
- 게시글 CRUD
- 이미지 S3 업로드
- 댓글 CRUD
- 찜하기 (좋아요)
- 팔로우
- 채팅

<br>
<br>
전체 코드 설명은 https://github.com/rlatmd0829/hanghae99_market 에서 볼수 있습니다.
<br>
<br>


### 프로젝트 목표

1. 테스트 코드 작성

2. @Builder 디자인 패턴, @valid 사용해 가독성 높이기.

3.  @Embeddable로 Adderss column을 구현해서 좀더 객체 지향적으로 Entity를 구현하고자했습니다.



### SignupReqeustDto
``` java
    @RequiredArgsConstructor
    @Getter
    @Setter
    public class SignupReqeustDto {

        @NotBlank(message = "아이디를 비워둘 수 없습니다.")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z[0-9]]{4,12}$",
                message = "아이디는 숫자와 영어를 포함한 4-12글자여야합니다.")
        private String username;

        @NotBlank(message = "비밀번호를 비워둘 수 없습니다.")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[0-9])(?=.*[$@$!%*#?&])[A-Za-z[0-9]$@$!%*#?&]{8,20}$",
                message = "비밀번호는 영문 대소문자와 숫자,특수문자를 포함한 8-20자여야합니다.")
        private String password;

        @NotBlank(message = "이메일을 비워둘 수 없습니다.")
        @Email(message = "메일 양식을 지켜주세요.")
        private String email;

        private String myself;

``` 
- @vaild 어노테이션을 이용해서 객체에서 유효성 검사를 처리합니다. (controller의 @RequestBody 에 @vaild 추가해서 사용.)
- @Patten : 정규식을 이용하여 유효성 검사 가능.
- @NotBlank : 빈값(공백 포함)인 경우 프론트에게 error메세지 반환.
- @Email : 이메일 양식 확인



### UserController

``` java
    /* 아이디(username) 중복 체크 */
    @GetMapping("/signups/username/{username}")
    public ResponseEntity username(@PathVariable String username){
        return ResponseEntity.ok(userService.usernameCheck(username));
    }

    /* 이메일 중복 체크 */
    @GetMapping("/signups/email/{email}")
    public ResponseEntity email(@PathVariable String email){
        return ResponseEntity.ok(userService.emailCheck(email));
    }
``` 
- 서버단에서 이메일과 아이디를  DB에 혹시라도 잘못된 데이터가 들어가지않도록 처리했습니다.



## 로그인 기능


### WebSecurityConfig
``` java
@Configuration
@EnableWebSecurity//시큐리티 활성화
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    /* 비밀번호 암호화 */
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 한글 인코딩
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        filter.setEncoding("UTF-8");
        filter.setForceEncoding(true);
        http.addFilterBefore(filter, CsrfFilter.class);


        http.csrf().disable();

        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  //session을 사용하지않겠다 .

                //jwt와 cors 관련 filter
                .and()
                    .addFilter(corsFilter)
                    .formLogin().disable()
                    .httpBasic().disable()
                    .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
                //권한 설정
                .authorizeRequests()
                    .antMatchers("/h2-console/**" ).permitAll()
                    .antMatchers("/user/**").permitAll()
                    //.antMatchers("/boards").access("hasRole('ROLE_USER') ")
                    .antMatchers("/boards/**").permitAll()
                    .antMatchers("/kakao/**").permitAll()
                    .anyRequest().permitAll();

    }

}
``` 

- JwtAuthenticationFilter(토큰발급)와 JwtAuthorizationFilter(토큰 인증)를 구현해 Spring security 필터가 작동되기전에 구현한 필터를 타도록 설정을 해두었습니다.
- jwt토큰을 사용함으로 session을 사용하지않고 구현한 필터를 통해 로그인과 권한 인증이 검증되도록 했습니다.
- 자세한 설명 >  https://goldcarrot2021.tistory.com/23?category=939711

### CorsConfig
```java
@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); //내 서버가 응답을 할때 json을 자바스크립트에서 처리할 수 있게 할지를 설정.
        config.addAllowedOrigin("*");// 모든 ip에 응답을 허용하겠다.
        config.addAllowedHeader("*");//모든 header에 응답을 허용하겠다.
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        config.addAllowedMethod("FETCH");

        config.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
        // 모든 api/** 주소는 이 config 설정을 따라간다.
        source.registerCorsConfiguration("/**",config);
        return new CorsFilter(source);

    }
}
```
- 다른 port의 서버와 요청을 주고발때 발생하는 cors를 해결하기위해 corsFilter를 구현했습니다. config.addAllowedOrigin("*")과  config.addAllowedMethod("*");을 같이 사용할 수 없는 이슈가 있어서 사용할 method를 등록해주는 방식으로 구현했습니다.


<br>
<br>
# 카카오 로그인기능

### KakaoLoginController

  - 카카오톡 로그인의 경우 카카오서버에서 카카오 유저의 정보를 반환해서 해당하는 유저가 없는 경우에 회원가입을 진행합니다 . 
  - 그 후 회원가입된 정보를 토대로 구현해둔 login을 callbak주소로 설정해 구현한 로그인 로직을 타도록 구현했습니다.

