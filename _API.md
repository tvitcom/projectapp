API: SYSTEM ROUTES(for basic authentication):

[ ]  /api/readme  GET            - Readme about current api routes and its current implementation statuses
[ ]  /admin/healthcheck GET      - Check system state
[ ]  /admin/dashboard GET        - Admin home page

FOR public guests:

      mwIsUser() (session.Get[id_user] == nil) => ->-> "/index.html"
[x]    / GET                        - Домашняя Home страничка сайта,
[x]    /soon GET                    - Coming soon страничка сайта,
[ ]    /signup GET|POST             - Обработка регистрации пользователя сайта,
[ ]    /useragreement  GET          - Ссылка на условия использования приложения User Agreement
[ ]    /privacy-policy  GET         - Ссылка на описание соблюдения GPDR приложения -> (Privacy manifesto in GPDR_POLICY.txt)
[ ]    /support  GET                - Ссылка на техподдержку Help
[ ]    /privacybox  GET|POST        - Ссылка на privacybox согласно GPDR_POLICY.txt
[x]    /auth/login GET|POST        	- Логин - аутентификация и авторизация пользователя,
[ ]    /auth/approvement/:secretlink GET - approvement by users email
[ ]    /auth/passwordrecover GET|POST    - Запрос восстановления пароля пользователя,
[ ]    /auth/passwordrecovered/:secretlink GET - Подтверждение смены пароля,


FOR Public guests:
[x]    /oauth/googleuser GET        - by Google Login after geting oauth credentials,

FOR USERS:

     mwIsNotUser() (id_user==0) => ->-> "/auth/signup"
[ ]   /corp/   GET                         - Welcome page for companies users
[ ]   /user/   GET                         - Welcome page
[ ]   /user/dashboard GET                  - Обзор проектов,
[ ]   /user/:project_id/adduser GET|POST   - Добавление профиля гостя.
[ ]   /user/profile/edit GET|POST          - Редактирование собственного профиля пользователя.
[ ]   /user/profile/password GET|POST      - Задание нового пароля пользователя.
[ ]   /user/logout GET|POST                - Выход.
[ ]   /user/signout/request GET            - Запрос удаления аккаунта.
[ ]   /user/signout/validation/:link GET   - Подтверждение удаления аккаунта.
