<!DOCTYPE html>

<html lang="ko">
<head>
  <meta charset="UTF-8" />

  <meta name="viewport" content="width=device-width, initial-scale=1.0" />

  <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css"
  />
  <!-- JS -->
  <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>

  <script>
    src = 'https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js';
    crossorigin = 'anonymous';
  </script>

 <title>정글그램 | 로그인 페이지</title>

  <!-- style -->
  <style type="text/css">
    * {
      font-family: "Stylish", sans-serif;
    }

    .wrap {
      width: 500px;
      margin: auto;
    }

    .titlegram {
      width: 500px;
      height: 200px;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    #register-box {
      width: 800px;
      margin: auto;
      padding: 5px;

      border-radius: 5px;
    }
  </style>
  <script>
     function formSubmit() {
        const token = sessionStorage.getItem('access-token');
        const myForm = $('#toMain');
        const hidden = $('#formHidden').val(token);

        myForm.submit();
    }

    $(document).ready(function () {
      $("#regibutton").click(function () {
          $("#register-box").toggle();
        });

      const token = sessionStorage.getItem('access-token');
      if (token) {
        $.ajax({
          type: "GET",
          url: "/check_token",
          headers: {
            'Authorization': 'Bearer ' + token
          },
          success: function (response) {
            console.log('토큰 유효성 검사 응답:', response);
            if (response.result === 'success') { 
              formSubmit();

            }
          },
          error: function () {
            alert('유효하지 않는 토큰 입니다.')
            console.log("토큰 유효성 검사 실패:", error); 
          }
        });
      } else {
        console.log('토큰이 없습니다');
      }
    });

    
    function signup() {
      $.ajax({
        type: 'POST',
        url: '/user/register',
        data: {
          id_give: $('#register-id').val(),
          pw_give: $('#register-password').val(),
        },
        success: function (response) {
          if (response.result === 'success') {
            alert('회원가입이 완료되었습니다.');
            insertMode(response._id);
          } else {
            alert('ID 중복 미확인');
          }
        },
        error: function () {
          alert('서버 오류!');
        },
      });
    }
    //route 변경: /users > /user
    function checkId() {
      $.ajax({
        type: 'GET',
        url: '/user/check_id',
        data: { id_give: $('#register-id').val() },
        success: function (response) {
          if (response.result === 'success') {
            alert('사용 가능한 ID입니다.');
          } else {
            alert('이미 사용 중인 ID입니다.');
          }
        },
        error: function () {
          alert('서버 오류!');
        },
      });
    }
    //route 변경: /users > /user
    function login() {
      $.ajax({
        type: 'POST',
        url: '/user/login',
        data: {
          id: $('#login-id').val(),
          pw: $('#login-password').val()
        },
        success: function (response) {
          if (response.result === 'success') {
            alert('로그인 성공!');
            //token 변수명 수정: token > access-token
            sessionStorage.setItem('access-token', response['access-token']);
            window.location.href = '/';

          } else {
            alert('아이디 또는 비밀번호를 잘못 입력했습니다.');
          }
        },
        error: function () {
          alert('서버 오류!');
        },
      });
    }

    function insertMode(_id) {
        $("#main-section").hide();
        $("#insert-section").show();
        $("#insert-button").on("click", function () {
          insert(_id);
        });
      }

    function insert(_id) {
        console.log(_id)
        $.ajax({
          type: "POST",
          url: "/users/insert",
          data: {
            _id: _id,
            name: $("#name").val(),
            age: $("#birth").val(),
            mbti: $("#mbti").val(),
            hobby: $("#hobby").val(),
            rgb: $("#color").val(),
            content: $("#selfcomment").val(),
          },
          success: function (response) {
            if (response.result === "success") {
              alert("정보 기입이 완료되었습니다.");
              console.log(response._id);
              window.location.href='/'
            } else {
              alert("계정이 없습니다(_id)");
            }
          },
          error: function () {
            alert("서버 오류!");
          },
        });
      }
  </script>
</head>

<body>
  <div id="main-section">
    <div class="wrap">
      <div class="titlegram">
        <p style="font-weight: bold; font-size: 5em; text-align: center">
          정글 그램
        </p>
      </div>

      <!-- 계정 입력부분 (로그인) -->

      <!-- id/pw 입력 -->

      <div class="field" style="margin-bottom: 50px">
        <div class="control">
          <input
            id="login-id"
            class="input"
            placeholder="아이디을 입력하세요"
          />
        </div>
      </div>

      <div class="field" style="margin-bottom: 50px">
        <div class="control">
          <input
            id="login-password"
            class="input"
            type="password"
            placeholder="비밀번호를 입력하세요"
          />
        </div>
      </div>

      <div class="field is-grouped">
        <div class="control">
          <button onclick="login()" class="button is-link">로그인</button>
        </div>
        <div class="control">
          <button class="button is-text" id="regibutton">
            회원가입
          </button>
        </div>
      </div>
    </div>

    <!-- 회원가입란 -->
    <div id="register-box" style="display: none">
      <hr class="mt-5 mb-5" />
      <div class="box">
        <h2 class="title is-4 has-text-centered mb-5">회원가입</h2>

        <!-- 아이디 -->
        <div class="field is-horizontal">
          <label class="label field-label is-normal">아이디</label>
          <div class="field-body">
            <div class="field is-grouped">
              <div class="control is-expanded has-icons-left has-icons-right">
                <input
                  id="register-id"
                  class="input"
                  placeholder="아이디를 입력하세요"
                />
                <span class="icon is-small is-left">
                  <i class="fas fa-envelope"></i>
                </span>
              </div>
              <div class="control">
                <button
                  onclick="checkId()"
                  class="button is-info is-outlined"
                  id="check-id-button"
                >
                  중복확인
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- 비밀번호 -->
        <div class="field is-horizontal">
          <label class="label field-label is-normal">비밀번호</label>
          <div class="field-body">
            <div class="control has-icons-left">
              <input
                id="register-password"
                class="input"
                type="password"
                placeholder="비밀번호를 입력하세요"
              />
              <span class="icon is-small is-left">
                <i class="fas fa-lock"></i>
              </span>
            </div>
          </div>
        </div>

        <!-- 가입버튼 -->
        <div class="field">
          <div class="control">
            <button
              onclick="signup()"
              class="button is-primary is-fullwidth"
              id="register-button"
            >
              가입
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="wrap" id="insert-section" style="display: none">
    <section class="section">
      <div class="container">
        <h1 class="title is-3">나를 소개해주세요!</h1>
        <div class="box">
          <div class="field">
            <label class="label" for="name">이름</label>
            <div class="control">
              <input class="input" type="text" id="name" />
            </div>
          </div>
          <div class="field">
            <label class="label" for="birth">생일</label>
            <div class="control">
              <input class="input" type="date" id="birth" />
            </div>
          </div>
          <div class="field">
            <label class="label" for="mbti">MBTI</label>
            <div class="control">
              <input class="input" type="text" id="mbti" />
            </div>
          </div>
          <div class="field">
              <label class="label" for="hobby">취미</label>
              <div class="control">
                  <input class="input" type="text" id="hobby" />
              </div>
          </div>
          <div class="field">
            <label class="label" for="pic">사진</label>
            <div class="control">
              <input class="input" type="file" id="pic" />
            </div>
          </div>
          <div class="field">
            <label class="label" for="color">좋아하는 색</label>
            <div class="control">
              <input class="input" type="color" id="color" />
            </div>
          </div>

          <div class="field">
            <label class="label" for="selfcomment">자기소개</label>
            <div class="control">
              <textarea class="textarea" id="selfcomment" rows="3"></textarea>
            </div>
          </div>
          <div class="field">
            <div class="control">
              <button class="button is-primary" id="insert-button">입력하기</button>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>

  <form id="toMain" action="main" method="POST" onclick="formSubmit()" style="display: none;">
    <input type="hidden" name="access-token" id="formHidden">
  </form>
</body>
</html>

</html>
