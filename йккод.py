import qrcode
import os

data = "Обычный QR-код"

fill_color = (0, 0, 0) #Цвет кода
back_color = (255, 255, 255) #Цвет фона

qr = qrcode.QRCode(
    version=3,
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=100,
    border=2
)

qr.add_data(data)
qr.make(fit=True)

img = qr.make_image(fill_color=fill_color, back_color=back_color)

img.save("custom_qrcode.png")
print("QR-код создан: custom_qrcode.png")
print(os.getcwd())

img.save("qrcode.png")
os.startfile("qrcode.png")