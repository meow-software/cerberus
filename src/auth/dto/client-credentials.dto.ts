import { IsString, Length } from 'class-validator';
import { SnowflakeDto } from './abstract/snowflake-abstract.dto';

export class ClientCredentialsDto extends SnowflakeDto{
  @IsString() 
  @Length(70) 
  clientSecret: string;
}
