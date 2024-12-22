$(document).ready(function(){ 
  $('.slider').slick({ 
    slidesToShow: 1, 
    slidesToScroll: 1, 
    autoplay: true, 
    autoplaySpeed: 2000, 
    infinite: true, 
    speed: 500, 
    customTransition: 'all 0.5s ease', 
    // Удаляем стандартные кнопки Slick 
    prevArrow: false, 
    nextArrow: false  
  }); 

  // Обработчики событий для стрелок 
  $('.arrow.prev').click(function(){ 
    $('.slider').slick('slickPrev'); 
  }); 

  $('.arrow.next').click(function(){ 
    $('.slider').slick('slickNext'); 
  }); 
});