#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: opencv_demo.py
@time: 2022/1/11 10:41
@project: python3-web-spider-learning
@desc: 8.2 使用OpenCV识别滑动验证码的缺口（P298~P303）
"""
import cv2

GAUSSIAN_BLUR_KERNEL_SIZE = (5, 5)
GAUSSIAN_BLUR_SIGMA_X = 0
CANNY_THRESHOLD1 = 200
CANNY_THRESHOLD2 = 450


def get_gaussian_blur_image(image):
    """
    得到高斯滤波处理后的图片
    """
    return cv2.GaussianBlur(image, GAUSSIAN_BLUR_KERNEL_SIZE, GAUSSIAN_BLUR_SIGMA_X)


def get_canny_image(image):
    """
    得到边缘检测处理后的图片
    """
    return cv2.Canny(image, CANNY_THRESHOLD1, CANNY_THRESHOLD2)


def get_contours(image):
    """
    得到轮廓信息
    """
    contours, _ = cv2.findContours(image, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_SIMPLE)
    return contours


def get_contour_area_thrshold(image_width, image_height):
    """
    定义目标轮廓的面积上下限
    """
    contour_area_min = (image_width * 0.15) * (image_height * 0.25) * 0.8
    contour_area_max = (image_width * 0.15) * (image_height * 0.25) * 1.2
    return contour_area_min, contour_area_max


def get_arc_threshold(image_width, image_height):
    """
    定义目标轮廓的周长上下限
    """
    arc_length_min = ((image_width * 0.15) + (image_height * 0.25)) * 2 * 0.8
    arc_length_max = ((image_width * 0.15) + (image_height * 0.25)) * 2 * 1.2
    return arc_length_min, arc_length_max


def get_offset_threshold(image_width):
    """
    定义缺口位置的偏移量上下限
    """
    offset_min = 0.2 * image_width
    offset_max = 0.85 * image_width
    return offset_min, offset_max


if __name__ == '__main__':
    image_raw = cv2.imread('files/slide_captcha.png')
    # 得到图片的宽高
    image_height, image_width, _ = image_raw.shape
    image_gaussian_blur = get_gaussian_blur_image(image_raw)
    cv2.imwrite('files/image_gaussian_blur.png', image_gaussian_blur)
    image_canny = get_canny_image(image_gaussian_blur)
    cv2.imwrite('files/image_canny.png', image_canny)
    contours = get_contours(image_canny)

    contour_area_min, contour_area_max = get_contour_area_thrshold(image_width, image_height)
    arc_length_min, arc_length_max = get_arc_threshold(image_width, image_height)
    offset_min, offset_max = get_offset_threshold(image_width)
    offset = None

    for contour in contours:
        x, y, w, h = cv2.boundingRect(contour)
        # 判断满足条件的缺口位置
        if contour_area_min < cv2.contourArea(contour) < contour_area_max and \
                arc_length_min < cv2.arcLength(contour, True) < arc_length_max and \
                offset_min < x < offset_max:
            # 用矩形框标注出来
            cv2.rectangle(image_raw, (x, y), (x + w, y + h), (0, 0, 255), 2)
            offset = x

    cv2.imwrite('files/image_label.png', image_raw)
    print('offset:', offset)
