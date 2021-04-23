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
- 개발 환경 : React, Spring
- 형상 관리 툴 : git
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

## 회원가입 기능

### 테스트 코드 작성
- 회원가입 기능 구현 시 테스크 코드를 작성했습니다. 

### User
```java

import javax.persistence.*;

@Getter
@NoArgsConstructor
@Entity(name = "user")
public class User {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    @Embedded
    private Adderss address;

    @Column
    private String myself;

    @Column(columnDefinition = "TEXT")
    private String profile_img;

    @Column(nullable = false)
    @Enumerated(value = EnumType.STRING)
    private UserRole role;

    @Column(nullable = true)
    private String kakaoId;

    //일반회원 reqequstDto
    @Builder
    public User(String username , String password,String email,String myself,String city,String street) {
        this.username = username;

        this.password = password;

        this.email = email;

        this.myself = myself;

        this.address = Adderss.builder()
                        .city(city)
                        .street(street)
                        .build();

        this.role = UserRole.ROLE_USER;
    }

    // Kakao 회원
    public User(String username,String password,String email,String kakaoId) {
        this.username = username;

        this.password = password;

        this.email = email;

        this.myself = "test";

        this.address = Adderss.builder()
                        .city("서울시")
                        .street("서울역")
                    .build();
        this.role = UserRole.ROLE_USER;
        this.kakaoId = kakaoId;
    }
}


```
- Builder 패턴을 사용해 좀 더 알아보기 명확한 코드를 짜고자 했습니다.


```java

@Getter
@RequiredArgsConstructor
@Embeddable
public class Adderss {
    private String city;
    private String street;

    @Builder
    public Adderss(String city, String street) {
        this.city = city;
        this.street = street;
    }
}


```
- @Embeddable로 Adderss column을 구현해서 좀더 객체 지향적으로 Entity를 구현하고자했습니다.


### SignupReqeustDtoTest
- @vaild을 사용한 유효성 검사가 제대로 되는 지 테스트 했습니다.(정상 케이스외 실패케이스까지 테스트한 전체 코드는 git에서 확인할 수 있습니다.)

```java
import com.hanghae.market.model.User;
import org.junit.jupiter.api.*;
import javax.validation.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;

class SignupReqeustDtoTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    public static void init() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Nested
    @DisplayName("회원생성")
    class CreateUser{

        private Long id;
        private String username;
        private String password;
        private String email;
        private String city;
        private String street;
        private String myself;


        @BeforeEach
        void setup(){

            id = 100L;
            username = "test33";
            password ="d23sdfsdDf3234523423&*#*";
            email ="test1@naver.com";
            city = "서울";
            street = "강남";
            myself = "자기소개";

        }

        @Test
        @DisplayName("정상케이스")
        void createUser_Normal(){
            //given

            SignupReqeustDto reqeustDto =SignupReqeustDto.builder()
                                                        .username(username)
                                                        .password(password)
                                                        .email(email)
                                                        .city(city)
                                                        .street(street)
                                                        .myself(myself)
                                                        .build();
            //when
            User user = reqeustDto.toEntity();

            //then
            assertNull(user.getId());
            assertEquals(username,user.getUsername());
            assertEquals(password,user.getPassword());
            assertEquals(email,user.getEmail());
            assertEquals(city, user.getAddress().getCity());
            assertEquals(street,user.getAddress().getStreet());
            assertEquals(myself,user.getMyself());
        }

```


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


### UserControllerTest
``` java
 @Test
        public void 회원가입() throws Exception {

            //given
            SignupReqeustDto reqeustDto = SignupReqeustDto.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .city(city)
                    .street(street)
                    .myself(myself)
                    .build();
            String url = "http://localhost:" + port + "/signups";

            //when
            ResponseEntity<Long> responseEntity = restTemplate.postForEntity(url, reqeustDto, Long.class);

            //then
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);

            List<User> all = userRepository.findAll();

            assertThat(all.get(0).getUsername()).isEqualTo(username);
            assertThat(bCryptPasswordEncoder.matches(all.get(0).getPassword(), password));
            assertThat(all.get(0).getEmail()).isEqualTo(email);
            assertThat(all.get(0).getMyself()).isEqualTo(myself);
            assertThat(all.get(0).getAddress().getCity()).isEqualTo(city);
            assertThat(all.get(0).getAddress().getStreet()).isEqualTo(street);
        }

``` 
- 회원가입과 관련된 테스트 코드를 작성하였습니다.

<br>
<br>

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

<br>

### JwtAuthenticationFilter
``` java
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login요청을 하면 로그인 시도를 위해서 실행되는 함수.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도 중.");


        try {
            //username,password를 받는다.
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            //PrincipalDetailsService의 loadUserByUseranme() 함수가 실행됨.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 : "+ principalDetails.getUser().getUsername());
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }


        return null;
    }

    //JWT토큰을 만들어서 response에 넘겨줌.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("인증 완료 토큰발급.");

        // user정보를 통해서 jwt토큰 생성.
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject(JwtProperties.SECRET)
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        /* body에 담을 유저 정보 생성*/
        ObjectMapper objectMapper = new ObjectMapper();
        UserInfoDto userInfoDto = new UserInfoDto(principalDetails.getUser().getId(),principalDetails.getUsername(),principalDetails.getUser().getEmail());
        String userInfoJson = objectMapper.writeValueAsString(userInfoDto);

        /* response에 토큰과 유저정보 담음.*/
        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX+jwtToken);
        response.addHeader("Content-type","applcation/json");
        response.getWriter().write(userInfoJson);
    }
}
```

- UsernamePasswordAuthenticationFilter 필터를 상속받아 구현했으며 토큰을 만들어서 발급하는 방식으로 되어있습니다.
- spring security는 attemptAuthentication 함수가 요청을 성공적으로 수행하면 successfulAuthentication가 작동하기때문에 successfulAuthentication를 상속받아 토큰을 발급해 유저정보를 reponse에 실어 보냅니다.


### JwtAuthorizationFilter


```java

//사용자가 jwt토큰을 보내면 토큰이 유효한지 확인
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을때 해당 필터 작동.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 요청 시도");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

        //header가 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }

        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX,"");

        // 토큰 만료됬을때 error잡기위해 try catch
        try{
            String username =
                    JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

            // JWT토큰 서명이 정상적으로 됨 (토큰 인증 ok)
            if(username != null){
                User user = userRepository.findByUsername(username);
                PrincipalDetails principalDetails = new PrincipalDetails(user);
                //임의로 token발급 -> username이 null이 아닌 경우라는 건 존재하는 회원이기떄문에.
                System.out.println(principalDetails.getAuthorities());
                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,null,principalDetails.getAuthorities());

                //강제로 시큐리티 세션에 접근하여 authentication객체 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            //서명이 정상적으로 안됬을 시에 필터를 타게함.
            chain.doFilter(request,response);

        }catch (Exception e){

            JSONObject json = new JSONObject();
            json.put("message", "tokenExpired");
            PrintWriter out = response.getWriter();
            out.print(json);


        }

    }
}

```
- 클라이언트에서 토큰을 header에 보내 요청을 하면 JwtAuthorizationFilter Filter를 타게 됩니다. jwt토큰이 유효한 토큰인지 확인한후 서명이 정상적으로 되면 유저가 존재하는지 확인한다음 강제로 시큐리티 session에 접근하여 authentication객체에 저장합니다
- session을 사용하지않겠다고 했는데 시큐리티 session에 접근하는 이유는 스프링 시큐리티 session이 authentication(즉,권한)과 관련된 객체를 관리하기때문입니다. 
- 권한 설정을 하지않으면 해당 코드는 필요하지않습니다.


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

```java
   //저장한 kakaoUser정보로 로그인요청
        if(kakaoLoginInfo != null){

            String username = kakaoLoginInfo.getKakaoId();
            String password = kakaoLoginInfo.getPassword();

            //HttpPost 요청
            HttpClient client = HttpClientBuilder.create().build();
            String postUrl ="http://localhost:8080/login";
            HttpPost httpPost = new HttpPost(postUrl);
            String data = "{" +
                    "\"username\": \""+username+"\", " +
                    "\"password\": \""+password+"\""+
                    "}";

            StringEntity entity = new StringEntity(data, ContentType.APPLICATION_FORM_URLENCODED);
            httpPost.setEntity(entity);

            HttpResponse responsePost = client.execute(httpPost);

            //HttpPost요청이 정상적으로 완료 되었다면
            if (responsePost.getStatusLine().getStatusCode() == 200) {

                // response Body에 있는 값을 꺼냄
                HttpEntity entitys = responsePost.getEntity();
                String content = EntityUtils.toString(entitys);

                // response header에 있는 token꺼냄
                String value = responsePost.getFirstHeader("Authorization").getValue();

                //다시 진짜 사용자의 요청에 리턴해 줄 response에 토큰과 사용자 정보를 넣는다.
                response.addHeader("Authonrazation", value);
                response.getWriter().write(content);

            } else {
                //에러 처리.
                response.getWriter().write("kakaoLoginError");
            }

        }else{
            //에러처리
            response.getWriter().write("kakaoUserNotFount");
        }
        
  ```
  - 카카오톡 로그인의 경우 카카오서버에서 카카오 유저의 정보를 반환해서 해당하는 유저가 없는 경우에 회원가입을 진행합니다 . 
  - 그 후 회원가입된 정보를 토대로 구현해둔 login로직을 타도록 HttpClinet를 이용해 서버에게 로그인 요청을 보내는 방식으로 구현되어있습니다.
  - KakaoLoginController 로직에서 강제 로그인 처리를 하지않는 이유는 jwt 로그인을 구현해둔 방식이 spring security의 필터를 타기전에 구현해둔 필터를 타야하는 방식이기때문에 
  - HttpClinet를 이용해 서버에 요청을 보내서 configure설정 대로 fileter를 타게 하고자했습니다.

