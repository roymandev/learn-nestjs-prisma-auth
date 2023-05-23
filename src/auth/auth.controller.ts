import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @Post('signin')
  signin(@Body() dto: AuthDto, @Req() req: Request, @Res() res: Response) {
    return this.authService.signin(dto, req, res);
  }

  @Get('signout')
  signout(@Req() req: Request, @Res() res: Response) {
    return this.authService.signout(req, res);
  }
}
