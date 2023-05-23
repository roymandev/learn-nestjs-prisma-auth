import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JWT_SECRET } from 'src/utils/constant';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (foundUser) throw new BadRequestException('User already exists');

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return { message: 'signup was successfull' };
  }

  async signin(dto: AuthDto, req: Request, res: Response) {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!foundUser) throw new BadRequestException('Wrong credentials');
    const isMatch = await this.comparePassword(
      password,
      foundUser.hashedPassword,
    );
    if (!isMatch) throw new BadRequestException('Wrong credentials');

    // sign jwt and return to the user
    const token = await this.signToken(foundUser.id, foundUser.email);

    res.cookie('token', token);

    return res.send({ message: 'Logged in successfully' });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');

    return res.send({ message: 'Logged out successfully' });
  }

  async hashPassword(password: string) {
    return await bcrypt.hash(password, 10);
  }

  async comparePassword(password: string, hashedPassword: string) {
    return await bcrypt.compare(password, hashedPassword);
  }

  async signToken(id: string, email: string) {
    const payload = { id, email };

    return this.jwt.signAsync(payload, {
      secret: JWT_SECRET,
    });
  }
}
