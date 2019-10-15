import sys
from PyQt5.QtWidgets import  *
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import QCoreApplication, QDateTime

class MyWidget(QWidget):
    def __init__(self):
        super().__init__()
        lbl_red = QLabel('Red')  # 라벨 설정
        lbl_green = QLabel('Green')
        lbl_blue = QLabel('Blue')

        lbl_red.setStyleSheet("color: red;"
                              "border-style: solid;"
                              "border-width: 2px;"
                              "border-color: #FA8072;"
                              "border-radius: 3px")
        lbl_green.setStyleSheet("color: green;"
                                "background-color: #7FFFD4")
        lbl_blue.setStyleSheet("color: blue;"
                               "background-color: #87CEFA;"
                               "border-style: dashed;"
                               "border-width: 3px;"
                               "border-color: #1E90FF")

        vbox = QVBoxLayout()
        vbox.addWidget(lbl_red)
        vbox.addWidget(lbl_green)
        vbox.addWidget(lbl_blue)
        self.setLayout(vbox)

class MyApp(QMainWindow):

    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):



        exitAction = QAction(QIcon('exit.png'),'Exit', self) # exitAction 아이콘, 설명 만듬
        exitAction.setShortcut('Ctrl+Q') # 숏컷 만듬
        exitAction.setStatusTip('Exit application') # 상태설명
        exitAction.triggered.connect(qApp.quit) # 누르면 앱 꺼짐

        self.statusBar() #상태바 만듬

        menubar = self.menuBar() # 메뉴바 만듬
        menubar.setNativeMenuBar(False) #기본 메뉴바를 삭제하고 커스텀 메뉴바를 만들기 위해 작성
        fileMenu = menubar.addMenu('&File') # file 메뉴를 만듬
        editMenu = menubar.addMenu('&Edit') # edit 메뉴를 만듬
        fileMenu.addAction(exitAction) # file 메뉴에 exitAction 메뉴를 추가함

        QToolTip.setFont((QFont('Sanserif', 12))) # 툴팁 추가
        self.setToolTip('This is a <b>QWidget</b> widget') # 툴팁 설명 추가

        """
        btn = QPushButton('Quit', self) # Quit 버튼 추가
        btn.move() # Quit 버튼 위치 변경
        btn.resize(btn.sizeHint()) # Quit 사이즈 변경
        btn.clicked.connect(QCoreApplication.instance().quit) # 버튼 클릭시 App 종료
        btn.setToolTip(('This is a <b>QPushbutton</b> widget')) # 버튼에 툴팁 설명 추가
        """

        now = QDateTime.currentDateTime() # 현재 시간값을 now에 가져옴
        self.statusBar().showMessage(now.toString('yyyy년 MM월 dd일 hh시 mm분 ss초에 수정완료')) #상태바 설명에 현재 시간 추가

        self.toolbar = self.addToolBar('Exit') # 툴바 추가
        self.toolbar.addAction(exitAction) # 툴바에 exitAction 추가

        wg = MyWidget() # mainwindow에 layout을 추가하려면 따로 class를 설정해서 넣어야 한다.
        self.setCentralWidget(wg)
        self.setGeometry(300,300,300,300)

        self.setWindowTitle("Title") # App 제목 추가
        self.resize(500,500) # App의 사이즈 변경
        self.center() # center 함수 호출
        self.setWindowIcon(QIcon('www.png')) # App의 아이콘을 WWW.PNG로 변경
        self.show() # App 나타내기


    def center(self): #Ccenter 함수 작성
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

if __name__ == '__main__':

    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec())